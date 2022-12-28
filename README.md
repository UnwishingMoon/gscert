# gscert - Generate self certificates
Gscert can help generate, use and renew self-signed certificates.

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

If no custom Certificate Authority is provided (private key included), a new Certificate Authority will be generated in the configuration folder, it defaults to the user home directory

```
Options:
	-help
		prints this help message

	-version
		prints the program version

	-ca CA_PATH
		path to a root certificate, if it does not exist, it will be generated in the provided position

	-ca-key CA_KEY_PATH
		path to the private key used to generate the root certificate, if it does not exist, it will be generated in the provided position

	-cert CERT_PATH
		path to a certificate, if it does not exist, it will be generated in the provided position

	-cert-key CERT_KEY_PATH
		path to the private key used to generate the certificate, if it does not exist, it will be generated in the provided position

	-csr CSR_PATH
		path to a certificate signing request, if it does not exists, it will be exported in the provided position

	-csr-key CSR_KEY_PATH
		path to the private key used for generating the certificate signing request, if it does not exists, it will be generated in the provided position

	-renew
		provide the flag if you want the certificates to be renewed in-place

	-org ORGANIZATION
		organization name to use during certificate creation (Default: "GSCert Security Certificates")

	-nginx
		reloads nginx after successful certificate generation or renewal

	-apache
		reloads apache2 after successful certificate generation or renewal

	-post-hook HOOK
		command or script to run after the certificate is generated, only executed on successul runs

	-config-dir CONFIG_DIR
		configuration path where CA files will be generated / read if not provided (default: ~/` + configFolder + `)

	-work-dir WORK_PATH
		change working directory inside the provided directory (default: current directory)
```

Examples:

```sh
$ gscert -d example.com -d example.org
    Generates a certificate for the provided domains with default CA

$ gscert -ca-key rootkey.pem -ca rootcert.pem -d example.com
    Generates a certificate for the provided domains with a custom CA

$ gscert -key cert-key.pem -cert cert.pem -d example.com
    Generates a certificate for the provided domains with a custom CA
```

# Inspired by

This project got inspired by https://github.com/FiloSottile/mkcert

I wanted something that could work exactly like certbot to deploy self-signed certificates