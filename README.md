# toolbox-scripts

A collection of utility scripts for system administration, automation, network operations, certificate handling, and more.

## 🔧 Scripts Included

- `renew_csr.sh`: Automatically generate a new CSR (Certificate Signing Request) based on the existing SSL certificate from a given URL, preserving SANs, algorithm and key parameters.

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
