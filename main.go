package main

import (
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"fmt"
	"os"
)

const (
	usage = `Usage:
	mkcert -d example.com -d example.org
	mkcert -key domainkey.pem -csr domaincsr.pem -ca-key rootkey.pem -d
	mkcert -key domainkey.pem -csr domaincsr.pem -ca rootca.pem -ca-key rootkey.pem
	`
	versionText    = `v0.1`
	configFolder   = `.mkcert`
	defaultRootKey = `root-key.pem`
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
		curdir, _    = os.Getwd()
		configdir, _ = os.UserConfigDir()

		help    = flag.Bool("help", false, "")
		version = flag.Bool("version", false, "")
		//	rootCertFlag = flag.String("ca", "root-cert.pem", "")
		rootKeyFlag = flag.String("cakey", "", "")
		//	csrFlag      = flag.String("csr", "csr.pem", "")
		//	certFlag     = flag.String("cert", "cert.pem", "")
		//	keyFlag      = flag.String("key", "key.pem", "")
		//	renew        = flag.Bool("renew", true, "")
		dir     = flag.String("dir", curdir, "")
		bits    = flag.Int("b", 4096, "")
		domains stringFlags

		rootKey *rsa.PrivateKey
		//rootCert x509.Certificate
	)
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), usage)
	}

	flag.Var(&domains, "d", "")

	flag.Parse()
	if *help {
		fmt.Println(usage)
		return
	}
	if *version {
		fmt.Println(versionText)
		return
	}
	if *dir != "" {
		err := os.Chdir(*dir)
		if err != nil {
			fmt.Println("Could not change into dir:", err)
			return
		}
	} else {
		dir = &curdir
	}

	if *rootKeyFlag == "" {
		// Checks if config folder exists
		if _, err := os.Stat(configdir + "/" + configFolder); os.IsNotExist(err) {
			os.Mkdir(configdir+"/.mkcert", 0755)
		}

		// Checks if root key exists
		if _, err := os.Stat(configdir + "/" + configFolder + "/" + defaultRootKey); os.IsNotExist(err) {
			// Generating a new key
			rootKey, err = rsa.GenerateKey(rand.Reader, *bits)
			if err != nil {
				fmt.Println("Could not generate Root Key:", err)
				return
			}
			os.WriteFile(configdir+"/"+configFolder+"/"+defaultRootKey, rootKey.N.Bytes(), 600)
		}

	} else {

	}

}
