# gscert - Generate self certificates
Gscert can help you generate, use and renew self-signed certificates.

# Features
```
Generation of:
    - Certification Authority
    - Certificate from a Certification Authority
    - Certificate Sign Request

Renew certificates 1 month prior to their expiration date
Post-success hooks (nginx, apache2 or custom command)
```

# Usage

```sh
gscert [options] [-d DOMAIN] [-d DOMAIN] ...
```

If no custom Certificate Authority is provided (private key included), a new Certificate Authority will be generated in the configuration folder (by default, it is located inside the home folder).

Options:
```
-help
    prints this help message

-ca CA_PATH
    path to a root certificate, if it does not exist, it will be generated in the provided position

-ca-key CA_KEY_PATH
    path to the private key used to generate the root certificate, if it does not exist, it will be generated in the provided position

-cert CERT_PATH
    path to a certificate, if it does not exist, it will be generated in the provided position

-key CERT_KEY_PATH
    path to the private key used to generate the certificate, if it does not exist, it will be generated in the provided position

-csr CSR_PATH
    path to a certificate signing request, if it does not exist, it will be exported in the provided position

-csr-key CSR_KEY_PATH
    path to the private key used for generating the certificate signing request, if it does not exist, it will be generated in the provided position

-renew
    provides the flag if you want the certificates to be renewed in-place

-org ORGANIZATION
    organization name to use during the certificate creation (Default: "GSCert Security Certificates")

-nginx
    reloads nginx after successful certificate generation or renewal

-apache
    reloads apache2 after successful certificate generation or renewal

-post-hook HOOK
    command or script to run after the certificate is generated, only executed on successfull runs

-config-dir CONFIG_DIR
    configuration path where CA files will be generated, read if not provided (default: ~/.gscert)

-work-dir WORK_PATH
    change working directory inside the provided directory (default: current directory)
```

Examples:

```sh
$ gscert -ca-key rootkey.pem -ca rootcert.pem -d example.com
    Generates a certificate for the provided domains with a custom CA

$ gscert -key cert-key.pem -cert cert.pem -d example.com
    Generates a certificate for the provided domains
```

# Inspired by

I wanted something that could work exactly like [certbot](https://github.com/certbot/certbot) to deploy self-signed certificates without installing anything