#!/bin/bash
#
# cosmos-fw.sh: Pare-feu dynamique pour validateurs Cosmos & relayers IBC sur Docker
# Gère la séparation du trafic P2P (public) et admin (Tailscale)
#

set -euo pipefail

# --- Configuration avec valeurs par défaut (override via env vars) ---
# Interface WAN (détection auto si non définie)
WAN_IFACE="${WAN_IFACE:-}"
# Interface Tailscale
TS_IFACE="${TS_IFACE:-tailscale0}"
# Suffixe des ports P2P (host port)
P2P_SUFFIX="${P2P_SUFFIX:-56}"
# Pattern pour les bridges Docker
DOCKER_BR_MATCH="${DOCKER_BR_MATCH:-br-+}"
DOCKER0_IFACE="docker0"
# Activer IPv6 (auto-détection si non défini)
ENABLE_IPv6="${ENABLE_IPv6:-auto}"
# Rate limit pour SSH
SSH_PORT="${SSH_PORT:-22}"
SSH_RATELIMIT_BURST="${SSH_RATELIMIT_BURST:-3}"
SSH_RATELIMIT_PER_MIN="${SSH_RATELIMIT_PER_MIN:-6}"
# Emplacement des sauvegardes et de la persistance
BACKUP_DIR="/root/iptables-backup"
PERSIST_DIR="/etc/iptables"
# Nombre max de ports par règle multiport
MULTIPORT_CHUNK_SIZE=15

# --- Fonctions utilitaires ---

log() {
    echo "[+] $@"
}

log_err() {
    echo "[!] $@" >&2
}

detect_wan_iface() {
    if [[ -z "$WAN_IFACE" ]]; then
        log "Détection de l'interface WAN..."
        # Tente de trouver l'interface pour une route IPv4 par défaut
        WAN_IFACE=$(ip route get 1.1.1.1 | grep -oP 'dev \\K\\S+')
        if [[ -z "$WAN_IFACE" ]]; then
            log_err "Impossible de détecter l'interface WAN. Spécifiez WAN_IFACE manuellement."
            exit 1
        fi
        log "Interface WAN détectée : $WAN_IFACE"
    fi
}

# --- Logique principale ---

# Fonction pour parser les ports publiés par Docker
# Sépare les ports en P2P (suffixe '56') et ADMIN (autres)
# Gère les ports uniques et les ranges.
# La décision se fait sur le HOST PORT, mais la règle s'applique sur le CONTAINER PORT.
get_docker_ports() {
    local proto=$1 # tcp ou udp
    local p2p_ports=()
    local admin_ports=()

    # Format: 0.0.0.0:3000-3002->4000-4002/tcp or 0.0.0.0:80->80/tcp
    local docker_ps_output
    if ! docker_ps_output=$(docker ps --format '{{.Ports}}'); then
        log_err "Erreur lors de l'exécution de 'docker ps'. Le démon Docker est-il en cours d'exécution ?"
        return 1
    fi

    echo "$docker_ps_output" | grep -E "\\->.*${proto}" | while read -r line; do
        # Extrait la partie host (0.0.0.0:3000-3002) et container (4000-4002)
        local host_part=$(echo "$line" | sed -E 's/->.*//')
        local container_part=$(echo "$line" | sed -E 's/.*->([0-9\\.\\:-]+)\\/.*//')

        # Extrait le port (ou le début de range)
        local host_port_start=$(echo "$host_part" | grep -oP '(?<=:)[0-9]+' | head -n1)
        local container_port_start=$(echo "$container_part" | grep -oP '^[0-9]+' | head -n1)

        # Gère les ranges
        local host_port_end=$(echo "$host_part" | grep -oP '(?<=-)[0-9]+' || echo "$host_port_start")

        if [[ -z "$host_port_start" || -z "$container_port_start" ]]; then
            continue
        fi

        local host_port_count=$((host_port_end - host_port_start))

        for i in $(seq 0 $host_port_count); do
            local current_host_port=$((host_port_start + i))
            local current_container_port=$((container_port_start + i))

            if [[ "$current_host_port" == *"$P2P_SUFFIX" ]]; then
                p2p_ports+=("$current_container_port")
            else
                admin_ports+=("$current_container_port")
            fi
        done
    done

    # Retourne les listes de ports, séparées par un point-virgule
    # uniq pour dédupliquer
    echo "$(echo "${p2p_ports[@]}" | tr ' ' '\\n' | sort -un | tr '\\n' ',' | sed 's/,$//');$(echo "${admin_ports[@]}" | tr ' ' '\\n' | sort -un | tr '\\n' ',' | sed 's/,$//')"
}

# Construit le corps des règles pour iptables-restore
build_ruleset() {
    local iptables_cmd=$1
    local ip_version=$2
    local wan_iface=$3
    local p2p_ports=$4
    local admin_ports=$5

    # Définition des adresses ANY en fonction de la version IP
    local any_addr="0.0.0.0/0"
    local icmp_type="icmp"
    if [ "$ip_version" = "6" ]; then
        any_addr="::/0"
        icmp_type="icmpv6"
    fi

    # Début du fichier de règles
    cat <<EOF
*filter
# --- Politiques par défaut : tout bloquer en entrée/transfert ---
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:DOCKER-USER - [0:0]

# --- Vider les règles existantes ---
-F INPUT
-F FORWARD
-F DOCKER-USER

# --- Chaîne INPUT (trafic destiné au host) ---
# Accepter le trafic déjà établi
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# Accepter le trafic sur l'interface loopback
-A INPUT -i lo -j ACCEPT
# Accepter ICMP (ping, etc.)
-A INPUT -p $icmp_type -j ACCEPT
# Accepter le trafic venant de Tailscale
-A INPUT -i $TS_IFACE -j ACCEPT
# Accepter le trafic pour le wireguard userspace de Tailscale
-A INPUT -p udp --dport 41641 -j ACCEPT
# Accepter SSH avec rate-limiting
-A INPUT -p tcp --dport $SSH_PORT -m conntrack --ctstate NEW -m recent --set --name SSH
-A INPUT -p tcp --dport $SSH_PORT -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount ${SSH_RATELIMIT_BURST} --name SSH -j DROP
-A INPUT -p tcp --dport $SSH_PORT -m conntrack --ctstate NEW -j ACCEPT

# --- Chaîne FORWARD (trafic routé, ex: vers Docker) ---
# Accepter le trafic déjà établi
-A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# Utiliser DOCKER-USER pour la logique custom, avant les règles Docker
-A FORWARD -j DOCKER-USER
# Autoriser le trafic de Docker vers l'extérieur
-A FORWARD -i $DOCKER0_IFACE -o $wan_iface -j ACCEPT
-A FORWARD -i $DOCKER_BR_MATCH -o $wan_iface -j ACCEPT
# Pour le trafic inter-conteneurs
-A FORWARD -i $DOCKER_BR_MATCH -o $DOCKER_BR_MATCH -j ACCEPT
-A FORWARD -i $DOCKER0_IFACE -o $DOCKER0_IFACE -j ACCEPT


# --- Chaîne DOCKER-USER (notre logique de filtrage custom) ---
# Accepter le trafic déjà établi (important pour le retour)
-A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Autoriser les ports ADMIN depuis Tailscale
$(echo "$admin_ports" | tr ',' '\\n' | xargs -r -n $MULTIPORT_CHUNK_SIZE | sed 's/ /,/g' | while read -r chunk; do
    [ -n "$chunk" ] && echo "-A DOCKER-USER -i $TS_IFACE -p tcp -m multiport --dports $chunk -j ACCEPT"
done)

# Autoriser les ports P2P depuis Internet
$(echo "$p2p_ports" | tr ',' '\\n' | xargs -r -n $MULTIPORT_CHUNK_SIZE | sed 's/ /,/g' | while read -r chunk; do
    [ -n "$chunk" ] && echo "-A DOCKER-USER -i $wan_iface -p tcp -m multiport --dports $chunk -j ACCEPT"
done)

# Autoriser les conteneurs à initier de nouvelles connexions vers l'extérieur
-A DOCKER-USER -i $DOCKER0_IFACE -o $wan_iface -m conntrack --ctstate NEW -j ACCEPT
-A DOCKER-USER -i $DOCKER_BR_MATCH -o $wan_iface -m conntrack --ctstate NEW -j ACCEPT

# Bloquer tout le reste du trafic entrant vers les conteneurs
-A DOCKER-USER -j DROP

COMMIT
EOF
}

# --- Point d'entrée ---
main() {
    if [ "$EUID" -ne 0 ]; then
        log_err "Ce script doit être exécuté en tant que root."
        exit 1
    fi

    COMMAND=${1:-"dry-run"} # "apply" ou "dry-run"

    # Vérification des dépendances
    for cmd in docker iptables ip; do
        if ! command -v $cmd &> /dev/null; then
            log_err "Commande requise non trouvée : $cmd. Veuillez l'installer."
            exit 1
        fi
    done

    detect_wan_iface

    # --- IPv4 ---
    log "--- Traitement IPv4 ---"
    local ports_v4
    if ! ports_v4=$(get_docker_ports tcp); then
        log_err "Impossible de récupérer les ports Docker. Abandon."
        exit 1
    fi
    local p2p_ports_v4=$(echo "$ports_v4" | cut -d';' -f1)
    local admin_ports_v4=$(echo "$ports_v4" | cut -d';' -f2)

    log "Ports P2P (suffixe ${P2P_SUFFIX}) détectés : ${p2p_ports_v4:-- Aucun -}"
    log "Ports Admin (autres) détectés         : ${admin_ports_v4:-- Aucun -}"

    local ruleset_v4
    ruleset_v4=$(build_ruleset "iptables" "4" "$WAN_IFACE" "$p2p_ports_v4" "$admin_ports_v4")

    if [ "$COMMAND" = "dry-run" ]; then
        log "Mode dry-run. Les règles suivantes seraient appliquées pour IPv4 :"
        echo "------------------------------------------------------------"
        echo "$ruleset_v4"
        echo "------------------------------------------------------------"
    elif [ "$COMMAND" = "apply" ]; then
        log "Sauvegarde des règles IPv4 actuelles..."
        mkdir -p "$BACKUP_DIR"
        local backup_file_v4="$BACKUP_DIR/rules.v4.$(date +%Y%m%d-%H%M%S)"
        if ! iptables-save > "$backup_file_v4"; then
            log_err "Échec de la sauvegarde des règles IPv4. Abandon."
            exit 1
        fi
        log "Sauvegarde créée : $backup_file_v4"

        log "Application des nouvelles règles IPv4..."
        if ! echo "$ruleset_v4" | iptables-restore -w -W 5 --noflush; then
            log_err "Échec de l'application des règles IPv4. TENTATIVE DE ROLLBACK."
            iptables-restore < "$backup_file_v4"
            exit 1
        fi

        log "Persistance des règles IPv4..."
        mkdir -p "$PERSIST_DIR"
        if ! iptables-save > "$PERSIST_DIR/rules.v4"; then
            log_err "Attention : impossible de persister les règles dans $PERSIST_DIR/rules.v4"
        fi
        log "Règles IPv4 appliquées et persistées avec succès."
    fi


    # --- IPv6 ---
    ipv6_enabled=false
    if [ "$ENABLE_IPv6" = "true" ] || ([ "$ENABLE_IPv6" = "auto" ] && command -v ip6tables &> /dev/null && [ -d /proc/sys/net/ipv6 ]); then
        ipv6_enabled=true
    fi

    if [ "$ipv6_enabled" = true ]; then
        log "--- Traitement IPv6 ---"
        # Note: Port parsing is identical for v6 as it's protocol-based
        local ruleset_v6
        ruleset_v6=$(build_ruleset "ip6tables" "6" "$WAN_IFACE" "$p2p_ports_v4" "$admin_ports_v4") # Re-using same port lists

        if [ "$COMMAND" = "dry-run" ]; then
            log "Mode dry-run. Les règles suivantes seraient appliquées pour IPv6 :"
            echo "------------------------------------------------------------"
            echo "$ruleset_v6"
            echo "------------------------------------------------------------"
        elif [ "$COMMAND" = "apply" ]; then
            log "Sauvegarde des règles IPv6 actuelles..."
            local backup_file_v6="$BACKUP_DIR/rules.v6.$(date +%Y%m%d-%H%M%S)"
            if ! ip6tables-save > "$backup_file_v6"; then
                log_err "Échec de la sauvegarde des règles IPv6. Abandon."
                # Pas de rollback v4 car il a déjà réussi
                exit 1
            fi
            log "Sauvegarde créée : $backup_file_v6"

            log "Application des nouvelles règles IPv6..."
            if ! echo "$ruleset_v6" | ip6tables-restore -w -W 5 --noflush; then
                 log_err "Échec de l'application des règles IPv6. TENTATIVE DE ROLLBACK."
                 ip6tables-restore < "$backup_file_v6"
                 exit 1
            fi

            log "Persistance des règles IPv6..."
            mkdir -p "$PERSIST_DIR"
            if ! ip6tables-save > "$PERSIST_DIR/rules.v6"; then
                log_err "Attention : impossible de persister les règles dans $PERSIST_DIR/rules.v6"
            fi
            log "Règles IPv6 appliquées et persistées avec succès."
        fi
    else
        log "IPv6 est désactivé ou non détecté. Ignoré."
    fi

    log "Opération terminée."
}

main "$@"
