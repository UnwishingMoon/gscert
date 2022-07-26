package main

import (
	"crypto/rand"
	"crypto/rsa"
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

	-key
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
		Change the bits of the key (Default: 4096)

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

	minBits = 4096
)

var versionText string = `v0.1`

type stringFlags []string

func (i *stringFlags) String() string {
	return fmt.Sprintf("%v", *i)
}

func (i *stringFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

// genReadKey Generate or reads a RSA key from a file
func genReadKey(file string, bits int) (*rsa.PrivateKey, error) {
	var key *rsa.PrivateKey

	if bits < minBits {
		bits = minBits
	}

	if _, err := os.Stat(file); errors.Is(err, fs.ErrNotExist) {

		// Generating a new key
		key, err = rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			fmt.Println("could not generate private key:", err)
			return nil, err
		}

		keyFile, err := os.Create(file)
		if err != nil {
			return nil, err
		}
		defer keyFile.Close()

		err = pem.Encode(keyFile, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})
		if err != nil {
			return nil, err
		}

	} else {

		// Using the found key
		if _, err = os.Stat(file); errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}

		keyString, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}

		keyPem, _ := pem.Decode(keyString)
		if keyPem.Type != "RSA PRIVATE KEY" {
			return nil, errors.New("input file is not a private key, found: " + keyPem.Type)
		}

		key, err = x509.ParsePKCS1PrivateKey(keyPem.Bytes)
		if err != nil {
			return nil, err
		}

	}

	return key, nil
}

// genReadCert Reads or generate a certificate from path with provided informations
func genReadCert(file string, priv *rsa.PrivateKey, rootPriv *rsa.PrivateKey, tmpl *x509.Certificate, rootTmpl *x509.Certificate) (*x509.Certificate, error) {
	var cert *x509.Certificate
	var err error

	if rootPriv == nil {
		rootPriv = priv
	}

	if rootTmpl == nil {
		rootTmpl = tmpl
	}

	if _, err = os.Stat(file); errors.Is(err, fs.ErrNotExist) {

		derCert, err := x509.CreateCertificate(rand.Reader, tmpl, rootTmpl, &priv.PublicKey, rootPriv)
		if err != nil {
			return nil, err
		}

		certFile, err := os.Create(file)
		if err != nil {
			return nil, err
		}
		defer certFile.Close()

		err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derCert})
		if err != nil {
			return nil, err
		}

		cert, err = x509.ParseCertificate(derCert)
		if err != nil {
			return nil, err
		}

	} else {
		if _, err := os.Stat(file); errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}

		certString, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}

		certPem, _ := pem.Decode(certString)
		if certPem.Type != "CERTIFICATE" {
			return nil, errors.New("input file is not a certificate, found: " + certPem.Type)
		}

		cert, err = x509.ParseCertificate(certPem.Bytes)
		if err != nil {
			return nil, err
		}
	}

	return cert, nil
}

// genReadCSR Reads or generate a CSR from a provided path
func genReadCSR(file string, priv *rsa.PrivateKey, tmpl *x509.CertificateRequest) (*x509.CertificateRequest, error) {
	var csr *x509.CertificateRequest
	var err error

	if _, err = os.Stat(file); errors.Is(err, fs.ErrNotExist) {
		derCSR, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
		if err != nil {
			return nil, err
		}

		csrFile, err := os.Create(file)
		if err != nil {
			return nil, err
		}
		defer csrFile.Close()

		err = pem.Encode(csrFile, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: derCSR})
		if err != nil {
			return nil, err
		}

		csr, err = x509.ParseCertificateRequest(derCSR)
		if err != nil {
			return nil, err
		}
	}

	return csr, nil
}

// renewCert Re-generates a certificate from a provided path
func renewCert(file string, priv *rsa.PrivateKey, rootPriv *rsa.PrivateKey, tmpl *x509.Certificate, rootTmpl *x509.Certificate) (*x509.Certificate, error) {
	var cert *x509.Certificate
	var err error

	if _, err = os.Stat(file); errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	// Reading the old certificate

	certString, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	certPem, _ := pem.Decode(certString)
	if certPem.Type != "CERTIFICATE" {
		return nil, errors.New("input file is not a certificate, found: " + certPem.Type)
	}

	cert, err = x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		return nil, err
	}

	tmpl.DNSNames = cert.DNSNames

	// Recreating the certificate

	derCert, err := x509.CreateCertificate(rand.Reader, tmpl, rootTmpl, &priv.PublicKey, rootPriv)
	if err != nil {
		return nil, err
	}

	certFile, err := os.Create(file)
	if err != nil {
		return nil, err
	}
	defer certFile.Close()

	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derCert})
	if err != nil {
		return nil, err
	}

	cert, err = x509.ParseCertificate(derCert)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func main() {
	var (
		// Predefined variables
		err     error
		runHook bool
		domains stringFlags // All domains listed by -d flag

		userDir, _ = os.UserHomeDir()                 // User home directory
		configDir  = path.Join(userDir, configFolder) // Full path to config folder

		// Flags
		help         = flag.Bool("help", false, "")                           // Help flag
		version      = flag.Bool("version", false, "")                        // Version flag
		rootCertFlag = flag.String("ca", "", "")                              // Path to CA certificate
		rootKeyFlag  = flag.String("ca-key", "", "")                          // Path to CA key
		csrFlag      = flag.String("csr", "", "")                             // Path to CSR
		csrKeyFlag   = flag.String("csr-key", "", "")                         // Path to CSR key
		certFlag     = flag.String("cert", "", "")                            // Path to certificate
		certKeyFlag  = flag.String("key", "", "")                             // Path to key
		renew        = flag.Bool("renew", false, "")                          // If the certificate should just be renewed in-place
		hookFlag     = flag.String("deploy-hook", "", "")                     // Command to execute after the deploy has been completed
		org          = flag.String("org", "GSCert Security Certificates", "") // Custom organization name
		bits         = flag.Int("b", minBits, "")                             // Number of bits for the key

		// Serialnumbers
		serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)
		rootSerial, _     = rand.Int(rand.Reader, serialNumberLimit)
		certSerial, _     = rand.Int(rand.Reader, serialNumberLimit)

		// CA
		rootKey  *rsa.PrivateKey
		rootCert *x509.Certificate
		rootTmpl = x509.Certificate{
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
		certKey  *rsa.PrivateKey
		certTmpl = x509.Certificate{
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
		csrKey  *rsa.PrivateKey
		csrTmpl = x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName:         *org,
				Country:            []string{"IT"},
				Province:           []string{"Italy"},
				Locality:           []string{"Italy"},
				Organization:       []string{*org},
				OrganizationalUnit: []string{"IT"},
			},
			SignatureAlgorithm: x509.SHA256WithRSA,
		}
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
		fmt.Println("Version:", versionText)
		return
	}

	// Checks if config folder exists
	if _, err := os.Stat(configDir); errors.Is(err, fs.ErrNotExist) {

		err := os.Mkdir(configDir, 0755)
		if err != nil {
			fmt.Println("could not create .gscert config folder in home directory:", err)
			return
		}
	}

	// Root Certificate //

	if *rootKeyFlag == "" {
		*rootKeyFlag = path.Join(configDir, dRootKeyName)
	}

	rootKey, err = genReadKey(*rootKeyFlag, *bits)
	if err != nil {
		fmt.Println("could not generate Root key:", err)
		return
	}

	if *rootCertFlag == "" {
		*rootCertFlag = path.Join(configDir, dRootCertName)
	}

	rootCert, err = genReadCert(*rootCertFlag, rootKey, nil, &rootTmpl, nil)
	if err != nil {
		fmt.Println("could not generate Root certificate:", err)
		return
	}

	// Certificate //

	if (*certKeyFlag == "" || *certFlag == "") && !(*certKeyFlag == "" && *certFlag == "") {
		fmt.Println("if one of cert or key flag is provided, the other must be provided too")
		return
	}

	if !*renew && (*certKeyFlag != "" || *certFlag != "") && len(domains) == 0 { // If no domain is provided
		fmt.Println("if cert and key flags are provided, domains must be provided too")
		return
	} else if (*certKeyFlag == "" && *certFlag == "") && len(domains) >= 1 { // If no cert and key flags are provided, but domains are provided
		*certKeyFlag = "key.pem"
		*certFlag = "cert.pem"
	}

	if *certKeyFlag != "" {

		certKey, err = genReadKey(*certKeyFlag, *bits)
		if err != nil {
			fmt.Println("could not generate certificate key:", err)
			return
		}

	}

	if *certFlag != "" {

		if *renew {

			_, err = renewCert(*certFlag, certKey, rootKey, &certTmpl, rootCert)
			if err != nil {
				fmt.Println("could not renew certificate:", err)
				return
			}

			runHook = true

		} else {

			certTmpl.DNSNames = domains

			_, err = genReadCert(*certFlag, certKey, rootKey, &certTmpl, rootCert)
			if err != nil {
				fmt.Println("could not generate certificate:", err)
				return
			}

		}

	}

	// CSR //

	if *csrKeyFlag != "" && *csrFlag != "" && len(domains) == 0 {
		fmt.Println("if csr and key flags are provided, domains must be provided too")
		return
	}

	if *csrKeyFlag == "" {
		*csrKeyFlag = "csr-key.pem"
	}

	if *csrFlag != "" {

		csrKey, err = genReadKey(*csrKeyFlag, *bits)
		if err != nil {
			fmt.Println("could not generate csr key:", err)
			return
		}

		csrTmpl.DNSNames = domains

		_, err = genReadCSR(*csrFlag, csrKey, &csrTmpl)
		if err != nil {
			fmt.Println("could not generate CSR:", err)
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
