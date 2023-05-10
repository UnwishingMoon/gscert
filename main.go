package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path"
	"time"
)

const (
	configFolder = `.gscert`

	dRootKeyName  = `root-key.pem`
	dRootCertName = `root-cert.pem`

	dCertKeyName = `key.pem`
	dCertName    = `cert.pem`

	dcsrName = `csr.pem`

	usage = `usage:
	gscert [options] [-d DOMAIN] [-d DOMAIN] ...

Gscert can help you generate, use and renew self-signed certificates.

Options:
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
		provide the flag if you want the certificates to be renewed in-place

	-rsa
		provide the flag if you want to generate keys using RSA4096 instead of ed25519

	-org ORGANIZATION
		organization name to use during the certificate creation (Default: "GSCert Security Certificates")

	-nginx
		reloads nginx after successful certificate generation or renewal

	-apache
		reloads apache2 after successful certificate generation or renewal

	-post-hook HOOK
		command or script to run after the certificate is generated, only executed on successfull runs

	-config-dir CONFIG_DIR
		configuration path where CA files will be generated, or read if not provided (default: ~/` + configFolder + `)

	-work-dir WORK_PATH
		change working directory inside the provided directory (default: current directory)



If no custom Certificate Authority is provided (private key included), a new Certificate Authority will be generated in the configuration folder (by default, it is located inside the home folder).


Examples:

	$ gscert -d example.com -d example.org
	Generates a certificate for the provided domains with default CA

	$ gscert -ca-key rootkey.pem -ca rootcert.pem -d example.com
	Generates a certificate for the provided domains with a custom CA

	$ gscert -key cert-key.pem -cert cert.pem -d example.com
	Generates a certificate for the provided domains with a custom CA

`
)

type domainFlags []string

func (i *domainFlags) String() string {
	return fmt.Sprintf("%v", *i)
}

func (i *domainFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func main() {
	var (
		err       error
		runHook   bool        // Should I run the deploy-hook
		domains   domainFlags // All domains listed by -d flag
		userDir   string      // Path to user home directory
		configDir string      // Full path to config directory

		// Flags
		helpFlag      = flag.Bool("help", false, "")                           // Help flag
		rootCertFlag  = flag.String("ca", "", "")                              // Path to CA certificate
		rootKeyFlag   = flag.String("ca-key", "", "")                          // Path to CA key
		csrFlag       = flag.String("csr", "", "")                             // Path to CSR
		csrKeyFlag    = flag.String("csr-key", "", "")                         // Path to CSR key
		certFlag      = flag.String("cert", "", "")                            // Path to certificate
		certKeyFlag   = flag.String("key", "", "")                             // Path to key
		renewFlag     = flag.Bool("renew", false, "")                          // If the certificate should just be renewed in-place
		nginxFlag     = flag.Bool("nginx", false, "")                          // Reloads nginx if provided and no configuration error is found
		apacheFlag    = flag.Bool("apache", false, "")                         // Reloads apache if provided and no configuration error is found
		postHookFlag  = flag.String("post-hook", "", "")                       // Command to execute after the deploy has been completed
		org           = flag.String("org", "GSCert Security Certificates", "") // Custom organization name
		workDirFlag   = flag.String("work-dir", "", "")                        // Path to working directory
		configDirFlag = flag.String("config-dir", "", "")                      // Path to custom configuration directory
		rsaFlag       = flag.Bool("rsa", false, "")                            // If should create keys using RSA4096 instead of ed25519

		// Serialnumbers
		serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)
		rootSerial, _     = rand.Int(rand.Reader, serialNumberLimit)
		certSerial, _     = rand.Int(rand.Reader, serialNumberLimit)

		// CA
		rootKey  crypto.PrivateKey
		rootTmpl = &x509.Certificate{
			NotBefore:             time.Now().UTC().AddDate(0, 0, -1),
			NotAfter:              time.Now().UTC().AddDate(10, 0, 0),
			SerialNumber:          rootSerial,
			BasicConstraintsValid: true,
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}

		// Certificate
		certKey  crypto.PrivateKey
		certTmpl = x509.Certificate{
			NotBefore:             time.Now().UTC().AddDate(0, 0, -1),
			NotAfter:              time.Now().UTC().AddDate(1, 0, 0),
			SerialNumber:          certSerial,
			BasicConstraintsValid: true,
			IsCA:                  false,
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		}

		// CSR
		csrKey  crypto.PrivateKey
		csrTmpl = x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   *org,
				Organization: []string{*org},
			},
			SignatureAlgorithm: x509.SignatureAlgorithm(x509.Ed25519),
		}
	)

	// Parsing flags
	flag.Var(&domains, "d", "")
	flag.Usage = func() {
		//fmt.Fprint(flag.CommandLine.Output(), usage)
	}
	flag.Parse()

	// Print help
	if *helpFlag {
		fmt.Print(usage)
		return
	}

	// Checks before executing the program //

	if *configDirFlag == "" { // Full path to config folder

		userDir, err = os.UserHomeDir() // if user home directory is not defined
		if err != nil {
			userDir = os.TempDir() // Overwrite user directory with the temp system directory
		}

		configDir = path.Join(userDir, configFolder)
	} else {
		configDir = *configDirFlag // Using user provided config folder
	}

	// Checks if config folder exists
	if _, err := os.Stat(configDir); errors.Is(err, os.ErrNotExist) {

		// Creating config folder if does not exists
		err := os.Mkdir(configDir, 0755)
		if err != nil {
			fmt.Println("could not create .gscert config folder in user home directory:", err)
			return
		}

	}

	// Changing inside user provided directory if provided
	if *workDirFlag != "" {
		err = os.Chdir(*workDirFlag)
		if err != nil {
			*workDirFlag = ""
		}
	}

	rootTmpl.Subject, certTmpl.Subject = pkix.Name{
		Organization:       []string{*org},
		CommonName:         *org,
		OrganizationalUnit: []string{*org},
	}, pkix.Name{
		Organization:       []string{*org},
		CommonName:         *org,
		OrganizationalUnit: []string{*org},
	}

	// FRoot key flag was not provided, using the default
	if *rootKeyFlag == "" {
		*rootKeyFlag = path.Join(configDir, dRootKeyName)
	}

	// Root certificate flag was not provided, using the default
	if *rootCertFlag == "" {
		*rootCertFlag = path.Join(configDir, dRootCertName)
	}

	// If a certificate flag exists and not the other
	if (*certKeyFlag == "" || *certFlag == "") && !(*certKeyFlag == "" && *certFlag == "") {
		fmt.Println("if one of cert or key flag is provided, the other must be provided too")
		return
	}

	// If is not a renew but certiticates flags are provided without domains
	if !*renewFlag && (*certKeyFlag != "" || *certFlag != "") && len(domains) == 0 {
		fmt.Println("if cert and key flags are provided but no renew flag, domains must be provided too")
		return
	} else if (*certKeyFlag == "" && *certFlag == "") && len(domains) >= 1 { // If no certificates flags are provided, but domains are provided
		*certKeyFlag = "key.pem"
		*certFlag = "cert.pem"
	}

	// Csr and key are provided but no domains found
	if *csrKeyFlag != "" && *csrFlag != "" && len(domains) == 0 {
		fmt.Println("if csr and key flags are provided, domains must be provided too")
		return
	}

	// Root Key //

	// Root key exists, I read it
	if _, err := os.Stat(*rootKeyFlag); err == nil {

		// Reading file found
		fileContents, err := os.ReadFile(*rootKeyFlag)
		if err != nil {
			fmt.Println("could not read root private key file:", err)
			return
		}

		// Decoding the key
		block, _ := pem.Decode(fileContents)
		if block.Type != "PRIVATE KEY" && block.Type != "RSA PRIVATE KEY" {
			fmt.Println(*rootKeyFlag, "input file is not a private key, found:", block.Type)
			return
		}

		// Parse the private key
		rootKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			fmt.Println("could not parse the root private key:", err)
			return
		}

	} else {

		// Generating a new key
		if *rsaFlag {
			rootKey, err = rsa.GenerateKey(rand.Reader, 4096)
		} else {
			_, rootKey, err = ed25519.GenerateKey(rand.Reader)
		}
		if err != nil {
			fmt.Println("could not generate root private key:", err)
			return
		}

		// Opening key file
		file, err := os.Create(*rootKeyFlag)
		if err != nil {
			fmt.Println("could not create root private key file:", err)
			return
		}
		defer file.Close()

		keyBytes, _ := x509.MarshalPKCS8PrivateKey(rootKey)

		// Writing to it
		err = pem.Encode(file, &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyBytes,
		})
		if err != nil {
			fmt.Println("could not write root private key file:", err)
			return
		}

	}

	// Root Certificate //

	// If file exists, I read it
	if _, err = os.Stat(*rootCertFlag); err == nil {

		// Reading file
		fileContents, err := os.ReadFile(*rootCertFlag)
		if err != nil {
			fmt.Println("could not read root certificate file:", err)
			return
		}

		// Decoding file contents
		pem, _ := pem.Decode(fileContents)
		if pem.Type != "CERTIFICATE" {
			fmt.Println(*rootCertFlag, "input file is not a certificate, found: ", pem.Type)
			return
		}

		rootTmpl, err = x509.ParseCertificate(pem.Bytes)
		if err != nil {
			fmt.Println("could not parse the previous certificate:", err)
			return
		}

	} else {

		// Generating the certificate
		fileContents, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.(crypto.Signer).Public(), rootKey)
		if err != nil {
			fmt.Println("could not create root certificate:", err)
			return
		}

		// Creating the certificate file
		file, err := os.Create(*rootCertFlag)
		if err != nil {
			fmt.Println("could not create root certificate file:", err)
			return
		}
		defer file.Close()

		// Encoding the certificate contents
		err = pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: fileContents})
		if err != nil {
			fmt.Println("could not write root certificate file", err)
			return
		}

	}

	// Certificate Key //

	if *certKeyFlag != "" {

		// Certificate key exists, I read it
		if _, err := os.Stat(*certKeyFlag); err == nil {

			// Reading file found
			fileContents, err := os.ReadFile(*certKeyFlag)
			if err != nil {
				fmt.Println("could not read cert private key file:", err)
				return
			}

			// Decoding the key
			pem, _ := pem.Decode(fileContents)
			if pem.Type != "PRIVATE KEY" && pem.Type != "RSA PRIVATE KEY" {
				fmt.Println(*certKeyFlag, "input file is not a private key, found:", pem.Type)
				return
			}

			// Parse the private key
			certKey, err = x509.ParsePKCS8PrivateKey(pem.Bytes)
			if err != nil {
				fmt.Println("could not parse the private key:", err)
				return
			}

		} else {
			// Generating a new key

			if *rsaFlag {
				certKey, err = rsa.GenerateKey(rand.Reader, 4096)
			} else {
				_, certKey, err = ed25519.GenerateKey(rand.Reader)
			}
			if err != nil {
				fmt.Println("could not generate cert private key:", err)
				return
			}

			// Opening key file
			file, err := os.Create(*certKeyFlag)
			if err != nil {
				fmt.Println("could not create cert private key file:", err)
				return
			}
			defer file.Close()

			keyBytes, _ := x509.MarshalPKCS8PrivateKey(certKey)

			// Writing to it
			err = pem.Encode(file, &pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: keyBytes,
			})
			if err != nil {
				fmt.Println("could not write cert private key file:", err)
				return
			}

		}

	}

	// Certificate //

	if *certFlag != "" {

		if *renewFlag {

			if _, err = os.Stat(*certFlag); errors.Is(err, os.ErrNotExist) {
				fmt.Println("could not find cert file:", err)
				return
			}

			// Reading the old certificate

			fileContents, err := os.ReadFile(*certFlag)
			if err != nil {
				fmt.Println("could not read cert file:", err)
				return
			}

			pemm, _ := pem.Decode(fileContents)
			if pemm.Type != "CERTIFICATE" {
				fmt.Println("input file is not a certificate, found:", pemm.Type)
				return
			}

			cert, err := x509.ParseCertificate(pemm.Bytes)
			if err != nil {
				fmt.Println("could not parse the previous certificate:", err)
				return
			}

			certTmpl.DNSNames = cert.DNSNames

			// Checks the old certificate expiration date

			if time.Until(cert.NotAfter) <= (time.Hour * 24 * 30) {

				// Recreating the certificate

				fileContents, err = x509.CreateCertificate(rand.Reader, &certTmpl, rootTmpl, certKey.(crypto.Signer).Public(), rootKey)
				if err != nil {
					fmt.Println("could not generate the new certificate:", err)
					return
				}

				file, err := os.Create(*certFlag)
				if err != nil {
					fmt.Println("could not create the new certificate file:", err)
					return
				}
				defer file.Close()

				err = pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: fileContents})
				if err != nil {
					fmt.Println("could not encode the new certificate:", err)
					return
				}

				cert, err = x509.ParseCertificate(fileContents)
				if err != nil {
					fmt.Println("could not parse the new certificate:", err)
					return
				}

				runHook = true

			}

		} else {

			certTmpl.DNSNames = domains

			// If file exists, I read it
			if _, err = os.Stat(*certFlag); err == nil {

				// Reading file
				fileContents, err := os.ReadFile(*certFlag)
				if err != nil {
					fmt.Println("could not read certificate file:", err)
					return
				}

				// Decoding file contents
				pem, _ := pem.Decode(fileContents)
				if pem.Type != "CERTIFICATE" {
					fmt.Println(*certFlag, "input file is not a certificate, found: ", pem.Type)
					return
				}

			} else {

				// Generating the certificate
				fileContents, err := x509.CreateCertificate(rand.Reader, &certTmpl, rootTmpl, certKey.(crypto.Signer).Public(), rootKey)
				if err != nil {
					fmt.Println("could not create certificate:", err)
					return
				}

				// Creating the certificate file
				file, err := os.Create(*certFlag)
				if err != nil {
					fmt.Println("could not create certificate file:", err)
					return
				}
				defer file.Close()

				// Encoding the certificate contents
				err = pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: fileContents})
				if err != nil {
					fmt.Println("could not write certificate file", err)
					return
				}

			}
		}
	}

	// CSR //

	if *csrFlag != "" {

		// CSR Key //

		if *csrKeyFlag == "" {
			*csrKeyFlag = "csr-key.pem"
		}

		// File already exists
		if _, err = os.Stat(*csrFlag); err == nil {
			fmt.Println("csr key already exists, please choose a new name:", err)
			return
		}

		// Generating a new key
		_, csrKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fmt.Println("could not generate cert private key:", err)
			return
		}

		// Opening key file
		file, err := os.Create(*csrKeyFlag)
		if err != nil {
			fmt.Println("could not create cert private key file:", err)
			return
		}
		defer file.Close()

		keyBytes, _ := x509.MarshalPKCS8PrivateKey(certKey)

		// Writing to it
		err = pem.Encode(file, &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyBytes,
		})
		if err != nil {
			fmt.Println("could not write cert private key file:", err)
			return
		}

		csrTmpl.DNSNames = domains

		// CSR Certificate //

		// File already exists
		if _, err = os.Stat(*csrFlag); err == nil {
			fmt.Println("csr certificate already exists, please choose a new name:", err)
			return
		}

		fileContents, err := x509.CreateCertificateRequest(rand.Reader, &csrTmpl, csrKey)
		if err != nil {
			return
		}

		file, err = os.Create(*csrFlag)
		if err != nil {
			return
		}
		defer file.Close()

		err = pem.Encode(file, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: fileContents})
		if err != nil {
			return
		}

		_, err = x509.ParseCertificateRequest(fileContents)
		if err != nil {
			return
		}

	}

	// Post Hooks //

	if !runHook {
		return
	}

	if *nginxFlag {
		cmd := exec.Command("/bin/sh", "-c", "nginx", "-s", "reload")

		if err := cmd.Run(); err != nil {
			fmt.Println("certificates deployed but could not run nginx post hook:", err)
			return
		}
	}

	if *apacheFlag {
		cmd := exec.Command("/bin/sh", "-c", "apache2ctl", "-k", "graceful")

		if err := cmd.Run(); err != nil {
			fmt.Println("certificates deployed but could not run apache post hook:", err)
			return
		}
	}

	if *postHookFlag != "" {
		cmd := exec.Command("/bin/sh", "-c", *postHookFlag)

		if err := cmd.Run(); err != nil {
			fmt.Println("could not execute deploy hook:", err)
			return
		}

	}

}
