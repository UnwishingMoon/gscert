package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"os/exec"
	"path"
	"time"
)

const (
	usage = `Usage:

	Options:
	-help
		Show this help message

	-version
		Show program version

	-ca
		Path to the root certificate

	-ca-key
		Path to the root private key

	-cert
		Path to the certificate

	-cert-key
		Path to the private key

	-csr
		Path to the certificate signing request

	-csr-key
		Path to the private key of the certificate signing request

	-renew
		If present attempt to renew the certificate in-place if it's going to expire in less than one month

	-org
		Organization name (Default: "GSCert Security Certificates")

	-b
		Change the bits of the key, can't be lower than the default (Default: 4096)

	-deploy-hook
		Path to a script or command to run after the certificate is generated (It is run only after a successfull renewal)


	Examples:

	$ gscert -d example.com -d example.org
	Generates a certificate for the provided domains with default CA

	$ gscert -ca-key rootkey.pem -ca rootcert.pem -d example.com
	Generates a certificate for the provided domains with a custom CA

	$ gscert -key cert-key.pem -cert cert.pem -d example.com
	Generates a certificate for the provided domains with a custom CA`

	configFolder = `.gscert`

	dRootKeyName  = `root-key.pem`
	dRootCertName = `root-cert.pem`

	dCertKeyName = `cert-key.pem`
	dCertName    = `cert.pem`

	dcsrName = `csr.pem`
)

var version string = "0.1"

type stringFlags []string

func (i *stringFlags) String() string {
	return fmt.Sprintf("%v", *i)
}

func (i *stringFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func main() {
	var (
		err     error
		runHook bool        // Should I run the deploy-hook
		domains stringFlags // All domains listed by -d flag

		userDir, _ = os.UserHomeDir()                 // User home directory
		configDir  = path.Join(userDir, configFolder) // Full path to config folder

		// Flags
		helpFlag     = flag.Bool("help", false, "")                           // Help flag
		versionFlag  = flag.Bool("version", false, "")                        // Version flag
		rootCertFlag = flag.String("ca", "", "")                              // Path to CA certificate
		rootKeyFlag  = flag.String("ca-key", "", "")                          // Path to CA key
		csrFlag      = flag.String("csr", "", "")                             // Path to CSR
		csrKeyFlag   = flag.String("csr-key", "", "")                         // Path to CSR key
		certFlag     = flag.String("cert", "", "")                            // Path to certificate
		certKeyFlag  = flag.String("cert-key", "", "")                        // Path to key
		renew        = flag.Bool("renew", false, "")                          // If the certificate should just be renewed in-place
		hookFlag     = flag.String("deploy-hook", "", "")                     // Command to execute after the deploy has been completed
		org          = flag.String("org", "GSCert Security Certificates", "") // Custom organization name

		// Serialnumbers
		serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)
		rootSerial, _     = rand.Int(rand.Reader, serialNumberLimit)
		certSerial, _     = rand.Int(rand.Reader, serialNumberLimit)

		// CA
		rootKey  *ecdsa.PrivateKey
		rootCert *x509.Certificate
		rootTmpl = &x509.Certificate{
			NotBefore:    time.Now().UTC().AddDate(0, 0, -1),
			NotAfter:     time.Now().UTC().AddDate(10, 0, 0),
			SerialNumber: rootSerial,
			Subject: pkix.Name{
				Organization: []string{*org},
				CommonName:   *org,
			},
			BasicConstraintsValid: true,
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}

		// Certificate
		certKey  *ecdsa.PrivateKey
		cert     *x509.Certificate
		certTmpl = &x509.Certificate{
			NotBefore:    time.Now().UTC().AddDate(0, 0, -1),
			NotAfter:     time.Now().UTC().AddDate(1, 0, 0),
			SerialNumber: certSerial,
			Subject: pkix.Name{
				Organization: []string{*org},
				CommonName:   *org,
			},
			BasicConstraintsValid: true,
		}

		// CSR
		csrKey *ecdsa.PrivateKey
		//csr     *x509.CertificateRequest
		csrTmpl = &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName:         *org,
				Country:            []string{"IT"},
				Province:           []string{"Italy"},
				Locality:           []string{"Italy"},
				Organization:       []string{*org},
				OrganizationalUnit: []string{"IT"},
			},
			SignatureAlgorithm: x509.ECDSAWithSHA512,
		}
	)

	// Parsing flags
	flag.Var(&domains, "d", "")
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), usage)
	}
	flag.Parse()

	// Print help
	if *helpFlag {
		fmt.Println(usage)
		return
	}

	// Show version
	if *versionFlag {
		fmt.Println("Version: v", version)
		return
	}

	// Checks before executing the program //

	// Checks if config folder exists
	if _, err := os.Stat(configDir); errors.Is(err, fs.ErrNotExist) {

		err := os.Mkdir(configDir, 0755)
		if err != nil {
			fmt.Println("could not create .gscert config folder in home directory:", err)
			return
		}

	}

	// Flag was not provided, using the default
	if *rootKeyFlag == "" {
		*rootKeyFlag = path.Join(configDir, dRootKeyName)
	}

	// Flag was not provided, using the default
	if *rootCertFlag == "" {
		*rootCertFlag = path.Join(configDir, dRootCertName)
	}

	// If exists one and not the other
	if (*certKeyFlag == "" || *certFlag == "") && !(*certKeyFlag == "" && *certFlag == "") {
		fmt.Println("if one of cert or key flag is provided, the other must be provided too")
		return
	}

	// If no domain is provided
	if !*renew && (*certKeyFlag != "" || *certFlag != "") && len(domains) == 0 {
		fmt.Println("if cert and key flags are provided, domains must be provided too")
		return
	} else if (*certKeyFlag == "" && *certFlag == "") && len(domains) >= 1 { // If no cert and key flags are provided, but domains are provided
		*certKeyFlag = "key.pem"
		*certFlag = "cert.pem"
	}

	// Csr and key are provided but not domains found
	if *csrKeyFlag != "" && *csrFlag != "" && len(domains) == 0 {
		fmt.Println("if csr and key flags are provided, domains must be provided too")
		return
	}

	// Root Key //

	// Root key exists, I read it
	if _, err := os.Stat(*rootKeyFlag); errors.Is(err, fs.ErrExist) {

		// Reading file found
		fileContents, err := os.ReadFile(*rootKeyFlag)
		if err != nil {
			fmt.Println("could not read root private key file:", err)
			return
		}

		// Decoding the key
		block, _ := pem.Decode(fileContents)
		if block.Type != "EC PRIVATE KEY" {
			fmt.Println(*rootKeyFlag, "input file is not a private key, found:", block.Type)
			return
		}

		// Parse the private key
		rootKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			fmt.Println("could not parse the root private key:", err)
			return
		}

	} else {

		// Generating a new key
		rootKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
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

		keyBytes, _ := x509.MarshalECPrivateKey(rootKey)

		// Writing to it
		err = pem.Encode(file, &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyBytes,
		})
		if err != nil {
			fmt.Println("could not write root private key file:", err)
			return
		}

	}

	// Root Certificate //

	// If file exists, I read it
	if _, err = os.Stat(*rootCertFlag); errors.Is(err, fs.ErrExist) {

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

		// Parsing certificate contents
		rootCert, err = x509.ParseCertificate(pem.Bytes)
		if err != nil {
			fmt.Println("could not parse root certificate:", err)
			return
		}

	} else {

		// Generating the certificate
		fileContents, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
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

		rootCert, err = x509.ParseCertificate(fileContents)
		if err != nil {
			fmt.Println("failed parsing the generated root certificate:", err)
			return
		}
	}

	// Certificate Key //

	if *certKeyFlag != "" {

		// Certificate key exists, I read it
		if _, err := os.Stat(*certKeyFlag); errors.Is(err, fs.ErrExist) {

			// Reading file found
			fileContents, err := os.ReadFile(*certKeyFlag)
			if err != nil {
				fmt.Println("could not read cert private key file:", err)
				return
			}

			// Decoding the key
			pem, _ := pem.Decode(fileContents)
			if pem.Type != "EC PRIVATE KEY" {
				fmt.Println(*certKeyFlag, "input file is not a private key, found:", pem.Type)
				return
			}

			// Parse the private key
			certKey, err = x509.ParseECPrivateKey(pem.Bytes)
			if err != nil {
				fmt.Println("could not parse the private key:", err)
				return
			}

		} else {

			// Generating a new key
			certKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
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

			keyBytes, _ := x509.MarshalECPrivateKey(certKey)

			// Writing to it
			err = pem.Encode(file, &pem.Block{
				Type:  "EC PRIVATE KEY",
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

		if *renew {

			if _, err = os.Stat(*certFlag); errors.Is(err, fs.ErrNotExist) {
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

			cert, err = x509.ParseCertificate(pemm.Bytes)
			if err != nil {
				fmt.Println("could not parse the previous certificate:", err)
				return
			}

			certTmpl.DNSNames = cert.DNSNames

			// Recreating the certificate

			fileContents, err = x509.CreateCertificate(rand.Reader, certTmpl, rootTmpl, &certKey.PublicKey, certKey)
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

		} else {

			certTmpl.DNSNames = domains

			// If file exists, I read it
			if _, err = os.Stat(*certFlag); errors.Is(err, fs.ErrExist) {

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

				// Parsing certificate contents
				cert, err = x509.ParseCertificate(pem.Bytes)
				if err != nil {
					fmt.Println("could not parse certificate:", err)
					return
				}

			} else {

				// Generating the certificate
				fileContents, err := x509.CreateCertificate(rand.Reader, certTmpl, rootCert, &certKey.PublicKey, &rootKey)
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

				cert, err = x509.ParseCertificate(fileContents)
				if err != nil {
					fmt.Println("failed parsing the generated certificate:", err)
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
		if _, err = os.Stat(*csrFlag); errors.Is(err, fs.ErrExist) {
			fmt.Println("csr key already exists, please choose a new name:", err)
			return
		}

		// Generating a new key
		csrKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
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

		keyBytes, _ := x509.MarshalECPrivateKey(certKey)

		// Writing to it
		err = pem.Encode(file, &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyBytes,
		})
		if err != nil {
			fmt.Println("could not write cert private key file:", err)
			return
		}

		csrTmpl.DNSNames = domains

		// CSR Certificate //

		// File already exists
		if _, err = os.Stat(*csrFlag); errors.Is(err, fs.ErrExist) {
			fmt.Println("csr certificate already exists, please choose a new name:", err)
			return
		}

		fileContents, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, csrKey)
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

	// Deploy Hook //

	if runHook && *hookFlag != "" {
		cmd := exec.Command("/bin/sh", "-c", *hookFlag)

		if err := cmd.Run(); err != nil {
			fmt.Println("could not execute deploy hook:", err)
			return
		}

	}

}
