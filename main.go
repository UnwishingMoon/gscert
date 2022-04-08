package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path"
	"time"
)

const (
	usage = `Usage:
	mkcert -d example.com -d example.org
	mkcert -key domainkey.pem -csr domaincsr.pem -ca-key rootkey.pem -d
	mkcert -key domainkey.pem -csr domaincsr.pem -ca rootca.pem -ca-key rootkey.pem
	`
	versionText     = `v0.1`
	configFolder    = `.gscert`
	defaultRootKey  = `root-key.pem`
	defaultRootCert = `root-cert.pem`
)

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
		// Predefined variables
		userDir, _ = os.UserHomeDir()
		configDir  = path.Join(userDir, configFolder)

		// Flags
		help         = flag.Bool("help", false, "")
		version      = flag.Bool("version", false, "")
		rootCertFlag = flag.String("ca", "", "")
		rootKeyFlag  = flag.String("cakey", "", "")
		//	csrFlag      = flag.String("csr", "csr.pem", "")
		//	certFlag     = flag.String("cert", "cert.pem", "")
		//	keyFlag      = flag.String("key", "key.pem", "")
		//	renew        = flag.Bool("renew", true, "")
		org     = flag.String("org", "GSCert Security Certificates", "")
		bits    = flag.Int("b", 4096, "")
		domains stringFlags

		// Serialnumbers
		serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)
		rootSerial, _     = rand.Int(rand.Reader, serialNumberLimit)
		certSerial, _     = rand.Int(rand.Reader, serialNumberLimit)

		// CA
		rootKey  *rsa.PrivateKey
		rootCert *x509.Certificate
		rootTmpl = x509.Certificate{
			NotBefore:    time.Now(),
			NotAfter:     time.Now().AddDate(10, 0, 0),
			SerialNumber: rootSerial,
			Subject: pkix.Name{
				Organization: []string{*org},
				CommonName:   *org,
			},
			BasicConstraintsValid: true,
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		}

		// Certificate
		certKey  *rsa.PrivateKey
		cert     *x509.Certificate
		certTmpl = x509.Certificate{
			NotBefore:    time.Now(),
			NotAfter:     time.Now().AddDate(1, 0, 0),
			SerialNumber: certSerial,
			Subject: pkix.Name{
				Organization: []string{*org},
				CommonName:   *org,
			},
			BasicConstraintsValid: true,
		}

		// CSR
		csr *x509.CertificateRequest
	)
	flag.Var(&domains, "d", "")
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), usage)
	}

	flag.Parse()

	// Help Flag
	if *help {
		fmt.Println(usage)
		return
	}

	// Version Flag
	if *version {
		fmt.Println(versionText)
		return
	}

	// Checks if config folder exists
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		os.Mkdir(configDir, 0755)
	}

	// Root Key Flag
	if *rootKeyFlag == "" {

		// Checks if root key exists
		if _, err := os.Stat(path.Join(configDir, defaultRootKey)); os.IsNotExist(err) {

			// Generating a new root key
			rootKey, err = rsa.GenerateKey(rand.Reader, *bits)
			if err != nil {
				fmt.Println("Could not generate Root Key:", err)
				return
			}

			os.WriteFile(path.Join(configDir, defaultRootKey), rootKey.N.Bytes(), 600)
		}

	} else {

		// Checks if root key exists
		if _, err := os.Stat(*rootKeyFlag); os.IsNotExist(err) {
			fmt.Println("Could not find Root Key file:", err)
			return
		}

		// Reads the root key
		rootKeyString, err := os.ReadFile(*rootKeyFlag)
		if err != nil {
			fmt.Println("Could not read Root Key file:", err)
			return
		}

		rootKeyPem, _ := pem.Decode(rootKeyString)
		rootKey, _ := x509.ParsePKCS1PrivateKey(rootKeyPem.Bytes)

	}

	// Root Cert Flag
	if *rootCertFlag == "" {

		// Checks if cert exists
		if _, err := os.Stat(path.Join(configDir, defaultRootCert)); os.IsNotExist(err) {

			cert, err := x509.CreateCertificate(rand.Reader, &rootCertTml, &rootCertTml, rootKey.PublicKey, rootKey)
			if err != nil {
				fmt.Println("Could not create Root Certificate:", err)
				return
			}

			rootCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})

			os.WriteFile(path.Join(configDir, defaultRootCert), rootCert, 600)
		}

	} else {

		// Checks if root cert exists
		if _, err := os.Stat(*rootCertFlag); os.IsNotExist(err) {
			fmt.Println("Could not find Root Key file:", err)
			return
		}

		// Reads the root cert
		rootCertString, err := os.ReadFile(*rootCertFlag)
		if err != nil {
			fmt.Println("Could not read Root Key file:", err)
			return
		}

		rootCertPem, _ := pem.Decode(rootCertString)
		rootCert, _ := x509.ParsePKCS1PrivateKey(rootCertPem.Bytes)

	}

}
