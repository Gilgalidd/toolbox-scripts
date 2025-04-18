
📄 csr-generator.sh

This script automates the renewal of a Certificate Signing Request (CSR) by retrieving the current certificate from a remote host and generating a new CSR and private key based on its parameters.
✅ Features

    Fetches current SSL certificate from a remote HTTPS service
    Automatically extracts:
        Common Name (CN)
        Organization (O)
        Subject Alternative Names (SANs)
        Key algorithm and size (RSA or EC)
    Interactive override for:
        CN, O, SANs
        RSA key size or EC curve
    Generates:
        CSR (renewed.csr)
        Private key (renewed.key)
        Optional JSON metadata (csr_info.json)
    All files are saved in a folder named after the host (e.g. example.com/)

🚀 Usage

./csr-generator.sh <hostname> [--json]
    --json : optional flag to generate and save all parameters as a JSON file.
    
📦 Example
./csr-generator.sh foo.com --json

Creates:

foo.com/
├── cert_from_site.pem
├── renewed.key
├── renewed.csr
├── csr_config.cnf
└── csr_info.json  # only if --json

⚠️ Requirements

    bash
    openssl
    jq
    awk, sed, iconv

📜 License

MIT License (or adapt as needed)
