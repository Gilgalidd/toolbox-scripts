# toolbox-scripts

A collection of utility scripts for system administration, automation, network operations, certificate handling, and more.

## 🔧 Scripts Included

- `renew_csr.sh`: Automatically generate a new CSR (Certificate Signing Request) based on the existing SSL certificate from a given URL, preserving SANs, algorithm and key parameters.
- `cosmos-fw.sh`: Dynamically configures iptables for Cosmos validators running on Docker, separating P2P (public) and admin (Tailscale) traffic. Comes with systemd units for automation.

> More scripts will be added over time...

## 🗂 Structure

Each script is self-contained and can be executed independently. Scripts are written in Bash and use common command-line tools (e.g. `openssl`, `curl`, `jq`).

## 📦 Requirements

Some scripts may require:
- `bash`
- `openssl`
- `jq`
- `curl`
- `sed`, `awk`

Check each script's header for usage instructions.

## 📄 License

This repository is licensed under the MIT License.
See [LICENSE](./LICENSE) for details.

---

## 🔥 Cosmos Validator Firewall (`cosmos-fw.sh`)

This script provides a robust firewall for Cosmos validators and IBC relayers running in Docker on Ubuntu 24.04. It dynamically adjusts firewall rules based on published Docker container ports, separating public P2P traffic from admin traffic tunneled over Tailscale.

### Core Logic
- **Default Drop Policy**: Blocks all incoming traffic by default.
- **Dynamic Port Analysis**: Reads currently published Docker ports.
- **P2P vs. Admin**: Ports ending in `56` (configurable) are classified as P2P and exposed to the WAN. All other ports are considered admin ports and are only accessible via the Tailscale interface.
- **Systemd Integration**: A service and a timer ensure the rules are applied on boot and refreshed every 60 seconds to adapt to container changes.

### Files

*   `cosmos-fw.sh`: The main script that applies the firewall rules.
*   `cosmos-fw.service`: systemd service to run the script.
*   `cosmos-fw.timer`: systemd timer to run the service periodically.

### Installation and Usage

Execute these commands on your server to deploy the firewall.

```bash
################################################################################
# 1. INSTALLATION
################################################################################

# -- Make the script executable --
chmod +x cosmos-fw.sh

# -- Place the files in their correct locations --
# NOTE: This assumes you are in the directory containing these files.
sudo cp cosmos-fw.sh /usr/local/bin/cosmos-fw.sh
sudo cp cosmos-fw.service /etc/systemd/system/cosmos-fw.service
sudo cp cosmos-fw.timer /etc/systemd/system/cosmos-fw.timer


# -- Disable UFW to avoid conflicts --
# UFW and iptables-nft do not coexist well. This script replaces UFW.
sudo ufw status # Check if UFW is active
sudo ufw disable


# -- Reload systemd and enable the services --
sudo systemctl daemon-reload
sudo systemctl enable cosmos-fw.service
sudo systemctl enable --now cosmos-fw.timer

# -- Check that the timer is active --
sudo systemctl list-timers | grep cosmos-fw

################################################################################
# 2. VERIFICATION AND TESTING
################################################################################

# -- Dry-run: check the rules that would be applied without touching anything --
# Useful for debugging.
sudo /usr/local/bin/cosmos-fw.sh dry-run

# -- Manual application and verification --
sudo /usr/local/bin/cosmos-fw.sh apply

# -- Check the DOCKER-USER chain (the core of our logic) --
# Should show multiport rules for P2P and Admin ports.
sudo iptables -S DOCKER-USER
# For a more detailed view with packet counters:
watch -n 2 'sudo iptables -L DOCKER-USER -v -n --line-numbers'

# -- Network tests (to be run from external machines) --

# A. FROM THE INTERNET (e.g., another VPS, not your Tailscale machine)
# Test P2P (MUST SUCCEED) - replace 22656 with one of your P2P ports
# nc -zv YOUR_PUBLIC_IP 22656

# Test ADMIN (MUST FAIL - timeout) - replace 22657 with one of your admin ports
# nc -zv YOUR_PUBLIC_IP 22657

# B. FROM A MACHINE ON YOUR TAILSCALE NETWORK
# Test ADMIN (MUST SUCCEED) - use the server's Tailscale IP
# nc -zv TAILSCALE_IP_SERVER 22657

################################################################################
# 3. SAFEGUARDS AND ROLLBACK
################################################################################

# -- Safe Apply: Application with a 90-second automatic rollback timer --
# If you lose SSH access, wait 90s and the connection should return.
# If everything works, cancel the timer with `sudo atrm <job_id>`.
echo "sudo iptables-restore < $(ls -1tr /root/iptables-backup/rules.v4.* | tail -n1)" | sudo at now + 90 seconds
# Then apply your rules:
sudo /usr/local/bin/cosmos-fw.sh apply
# If everything is OK after 30-60s, list (`sudo atq`) and remove (`sudo atrm <ID>`) the rollback job.

# -- Manual Rollback (if something went wrong) --

# Option 1: Restore the very last backup
LATEST_V4_BACKUP=$(ls -1tr /root/iptables-backup/rules.v4.* | tail -n1)
LATEST_V6_BACKUP=$(ls -1tr /root/iptables-backup/rules.v6.* | tail -n1)
echo "Restoring $LATEST_V4_BACKUP and $LATEST_V6_BACKUP..."
sudo iptables-restore < "$LATEST_V4_BACKUP"
if [ -f "$LATEST_V6_BACKUP" ]; then sudo ip6tables-restore < "$LATEST_V6_BACKUP"; fi

# Option 2: Quickly neutralize filtering on Docker (lets traffic through)
# Useful if the problem is only with DOCKER-USER.
sudo iptables -F DOCKER-USER
sudo iptables -A DOCKER-USER -j RETURN # Return control to the DOCKER chain
```
