// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command mkcert is a simple zero-config tool to make development certificates.
package mkcert

import (
	"crypto"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/mail"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"

	"golang.org/x/net/idna"
)

const shortUsage = `Usage of mkcert:

	$ mkcert -install
	Install the local CA in the system trust store.

	$ mkcert example.org
	Generate "example.org.pem" and "example.org-key.pem".

	$ mkcert example.com myapp.dev localhost 127.0.0.1 ::1
	Generate "example.com+4.pem" and "example.com+4-key.pem".

	$ mkcert "*.example.it"
	Generate "_wildcard.example.it.pem" and "_wildcard.example.it-key.pem".

	$ mkcert -uninstall
	Uninstall the local CA (but do not delete it).

`

const advancedUsage = `Advanced options:

	-cert-file FILE, -key-file FILE, -p12-file FILE
	    Customize the output paths.

	-client
	    Generate a certificate for client authentication.

	-ecdsa
	    Generate a certificate with an ECDSA key.

	-pkcs12
	    Generate a ".p12" PKCS #12 file, also know as a ".pfx" file,
	    containing certificate and key for legacy applications.

	-csr CSR
	    Generate a certificate based on the supplied CSR. Conflicts with
	    all other flags and arguments except -install and -cert-file.

	-CAROOT
	    Print the CA certificate and key storage location.

	$CAROOT (environment variable)
	    Set the CA certificate and key storage location. (This allows
	    maintaining multiple local CAs in parallel.)

	$TRUST_STORES (environment variable)
	    A comma-separated list of trust stores to install the local
	    root CA into. Options are: "system", "java" and "nss" (includes
	    Firefox). Autodetected by default.

`

// Version can be set at link time to override debug.BuildInfo.Main.Version,
// which is "(devel)" when building from within the module. See
// golang.org/issue/29814 and golang.org/issue/29228.
var Version string

func main() {
	if len(os.Args) == 1 {
		fmt.Print(shortUsage)
		return
	}
	log.SetFlags(0)
	var (
		installFlag   = flag.Bool("install", false, "")
		uninstallFlag = flag.Bool("uninstall", false, "")
		pkcs12Flag    = flag.Bool("pkcs12", false, "")
		ecdsaFlag     = flag.Bool("ecdsa", false, "")
		clientFlag    = flag.Bool("client", false, "")
		helpFlag      = flag.Bool("help", false, "")
		carootFlag    = flag.Bool("CAROOT", false, "")
		csrFlag       = flag.String("csr", "", "")
		certFileFlag  = flag.String("cert-file", "", "")
		keyFileFlag   = flag.String("key-file", "", "")
		p12FileFlag   = flag.String("p12-file", "", "")
		versionFlag   = flag.Bool("version", false, "")
	)
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), shortUsage)
		fmt.Fprintln(flag.CommandLine.Output(), `For more options, run "mkcert -help".`)
	}
	flag.Parse()
	if *helpFlag {
		fmt.Print(shortUsage)
		fmt.Print(advancedUsage)
		return
	}
	if *versionFlag {
		if Version != "" {
			fmt.Println(Version)
			return
		}
		if buildInfo, ok := debug.ReadBuildInfo(); ok {
			fmt.Println(buildInfo.Main.Version)
			return
		}
		fmt.Println("(unknown)")
		return
	}
	if *carootFlag {
		if *installFlag || *uninstallFlag {
			log.Fatalln("ERROR: you can't set -[un]install and -CAROOT at the same time")
		}
		fmt.Println(getCAROOT())
		return
	}
	if *installFlag && *uninstallFlag {
		log.Fatalln("ERROR: you can't set -install and -uninstall at the same time")
	}
	if *csrFlag != "" && (*pkcs12Flag || *ecdsaFlag || *clientFlag) {
		log.Fatalln("ERROR: can only combine -csr with -install and -cert-file")
	}
	if *csrFlag != "" && flag.NArg() != 0 {
		log.Fatalln("ERROR: can't specify extra arguments when using -csr")
	}
	(&MKCert{
		InstallMode: *installFlag, UninstallMode: *uninstallFlag, csrPath: *csrFlag,
		pkcs12: *pkcs12Flag, ecdsa: *ecdsaFlag, client: *clientFlag,
		CertFile: *certFileFlag, KeyFile: *keyFileFlag, p12File: *p12FileFlag,
	}).Run(flag.Args())
}

const rootName = "rootCA.pem"
const rootKeyName = "rootCA-key.pem"

type MKCert struct {
	InstallMode, UninstallMode bool
	pkcs12, ecdsa, client      bool
	KeyFile, CertFile, p12File string
	csrPath                    string
	EnabledStores              []string

	CAROOT string
	caCert *x509.Certificate
	caKey  crypto.PrivateKey

	// The system cert pool is only loaded once. After installing the root, checks
	// will keep failing until the next execution. TODO: maybe execve?
	// https://github.com/golang/go/issues/24540 (thanks, myself)
	ignoreCheckFailure bool
}

func (m *MKCert) Load() error {
	m.CAROOT = getCAROOT()
	if m.CAROOT == "" {
		return errors.New("failed to find the default CA location, set one as the CAROOT env var")
	}
	if err := os.MkdirAll(m.CAROOT, 0755); err != nil {
		return fmt.Errorf("failed to create the CAROOT: %w", err)
	}
	if err := m.loadCA(); err != nil {
		return err
	}
	return nil
}

func (m *MKCert) Run(args []string) error {
	m.CAROOT = getCAROOT()
	if m.CAROOT == "" {
		return errors.New("failed to find the default CA location, set one as the CAROOT env var")
	}
	if err := os.MkdirAll(m.CAROOT, 0755); err != nil {
		return fmt.Errorf("failed to create the CAROOT: %w", err)
	}
	if err := m.loadCA(); err != nil {
		return err
	}

	// if m.InstallMode {
	// 	m.Install()
	// 	if len(args) == 0 {
	// 		return
	// 	}
	// } else if m.UninstallMode {
	// 	m.Uninstall()
	// 	return
	// } else {
	// 	var warning bool
	// 	if m.storeEnabled("system") && !m.CheckPlatform() {
	// 		warning = true
	// 		log.Println("Note: the local CA is not installed in the system trust store.")
	// 	}
	// 	if m.storeEnabled("nss") && hasNSS && CertutilInstallHelp != "" && !m.CheckNSS() {
	// 		warning = true
	// 		log.Printf("Note: the local CA is not installed in the %s trust store.", NSSBrowsers)
	// 	}
	// 	if m.storeEnabled("java") && hasJava && !m.checkJava() {
	// 		warning = true
	// 		log.Println("Note: the local CA is not installed in the Java trust store.")
	// 	}
	// 	if warning {
	// 		log.Println("Run \"mkcert -install\" for certificates to be trusted automatically ⚠️")
	// 	}
	// }

	// if m.csrPath != "" {
	// 	m.makeCertFromCSR()
	// 	return
	// }

	// if len(args) == 0 {
	// 	flag.Usage()
	// 	return
	// }

	hostnameRegexp := regexp.MustCompile(`(?i)^(\*\.)?[0-9a-z_-]([0-9a-z._-]*[0-9a-z_-])?$`)
	for i, name := range args {
		if ip := net.ParseIP(name); ip != nil {
			continue
		}
		if email, err := mail.ParseAddress(name); err == nil && email.Address == name {
			continue
		}
		if uriName, err := url.Parse(name); err == nil && uriName.Scheme != "" && uriName.Host != "" {
			continue
		}
		punycode, err := idna.ToASCII(name)
		if err != nil {
			return fmt.Errorf("%q is not a valid hostname, IP, URL or email: %s", name, err)
		}
		args[i] = punycode
		if !hostnameRegexp.MatchString(punycode) {
			return fmt.Errorf("%q is not a valid hostname, IP, URL or email", name)
		}
	}

	return m.makeCert(args)
}

func getCAROOT() string {
	if env := os.Getenv("CAROOT"); env != "" {
		return env
	}

	var dir string
	switch {
	case runtime.GOOS == "windows":
		dir = os.Getenv("LocalAppData")
	case os.Getenv("XDG_DATA_HOME") != "":
		dir = os.Getenv("XDG_DATA_HOME")
	case runtime.GOOS == "darwin":
		dir = os.Getenv("HOME")
		if dir == "" {
			return ""
		}
		dir = filepath.Join(dir, "Library", "Application Support")
	default: // Unix
		dir = os.Getenv("HOME")
		if dir == "" {
			return ""
		}
		dir = filepath.Join(dir, ".local", "share")
	}
	return filepath.Join(dir, "mkcert")
}

func (m *MKCert) Install() error {
	if m.storeEnabled("system") {
		if m.CheckPlatform() {
			log.Print("the local CA is already installed in the system trust store")
		} else {
			if err := m.installPlatform(); err != nil {
				return fmt.Errorf("failed to install local CA in system trust store: %w", err)
			}
			m.ignoreCheckFailure = true // TODO: replace with a check for a successful install
		}
	}
	if m.storeEnabled("nss") && hasNSS {
		if m.CheckNSS() {
			log.Printf("the local CA is already installed in the %s trust store", NSSBrowsers)
		} else {
			if hasCertutil {
				if err := m.installNSS(); err != nil {
					return fmt.Errorf("failed to install local CA in the %s trust store", NSSBrowsers)
				}
			} else if CertutilInstallHelp == "" {
				log.Printf(`note: %s support is not available on your platform.`, NSSBrowsers)
				return nil
			} else if !hasCertutil {
				log.Printf(`warning: "certutil" is not available, so the CA can't be automatically installed in %s`, NSSBrowsers)
				log.Printf(`install "certutil" with "%s" and re-run the install`, CertutilInstallHelp)
				return nil
			}
		}
	}
	return nil
	// if m.storeEnabled("java") && hasJava {
	// 	if m.checkJava() {
	// 		log.Println("The local CA is already installed in Java's trust store! 👍")
	// 	} else {
	// 		if hasKeytool {
	// 			m.installJava()
	// 			log.Println("The local CA is now installed in Java's trust store! ☕️")
	// 		} else {
	// 			log.Println(`Warning: "keytool" is not available, so the CA can't be automatically installed in Java's trust store! ⚠️`)
	// 		}
	// 	}
	// }
	// log.Print("")
}

func (m *MKCert) Uninstall() error {
	if m.storeEnabled("nss") && hasNSS {
		if hasCertutil {
			if err := m.uninstallNSS(); err != nil {
				return fmt.Errorf("failed to uninstall local CA from the %s trust store(s): %w", NSSBrowsers, err)
			}
		} else if CertutilInstallHelp != "" {
			log.Print("")
			log.Printf(`warning: "certutil" is not available, so the CA can't be automatically uninstalled from %s (if it was ever installed)!`, NSSBrowsers)
			log.Printf(`you can install "certutil" with "%s" and re-run uninstall`, CertutilInstallHelp)
			log.Print("")
		}
	}
	// if m.storeEnabled("java") && hasJava {
	// 	if hasKeytool {
	// 		m.uninstallJava()
	// 	} else {
	// 		log.Print("")
	// 		log.Println(`Warning: "keytool" is not available, so the CA can't be automatically uninstalled from Java's trust store (if it was ever installed)! ⚠️`)
	// 		log.Print("")
	// 	}
	// }
	if m.storeEnabled("system") {
		if err := m.uninstallPlatform(); err != nil {
			return fmt.Errorf("failed to uninstall the local CA from the system trust store: %w", err)
		}
	} else if m.storeEnabled("nss") && hasCertutil {
		log.Printf("the local CA is now uninstalled from the %s trust store(s)", NSSBrowsers)
		log.Print("")
	}
	return nil
}

func (m *MKCert) CheckPlatform() bool {
	if m.ignoreCheckFailure {
		return true
	}

	_, err := m.caCert.Verify(x509.VerifyOptions{})
	return err == nil
}

func (m *MKCert) storeEnabled(name string) bool {
	if len(m.EnabledStores) != 0 {
		for _, store := range m.EnabledStores {
			if store == name {
				return true
			}
		}
		return false
	}
	stores := os.Getenv("TRUST_STORES")
	if stores == "" {
		return true
	}
	for _, store := range strings.Split(stores, ",") {
		if store == name {
			return true
		}
	}
	return false
}

func fatalIfErr(err error, msg string) {
	if err != nil {
		log.Fatalf("ERROR: %s: %s", msg, err)
	}
}

func fatalIfCmdErr(err error, cmd string, out []byte) {
	if err != nil {
		log.Fatalf("ERROR: failed to execute \"%s\": %s\n\n%s\n", cmd, err, out)
	}
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func binaryExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

var sudoWarningOnce sync.Once

func commandWithSudo(cmd ...string) *exec.Cmd {
	if u, err := user.Current(); err == nil && u.Uid == "0" {
		return exec.Command(cmd[0], cmd[1:]...)
	}
	if !binaryExists("sudo") {
		sudoWarningOnce.Do(func() {
			log.Println(`Warning: "sudo" is not available, and mkcert is not running as root. The (un)install operation might fail. ⚠️`)
		})
		return exec.Command(cmd[0], cmd[1:]...)
	}
	return exec.Command("sudo", append([]string{"--prompt=Sudo password:", "--"}, cmd...)...)
}
