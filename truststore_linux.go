// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mkcert

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

var (
	FirefoxProfiles = []string{os.Getenv("HOME") + "/.mozilla/firefox/*",
		os.Getenv("HOME") + "/snap/firefox/common/.mozilla/firefox/*"}
	NSSBrowsers = "Firefox and/or Chrome/Chromium"

	SystemTrustFilename string
	SystemTrustCommand  []string
	CertutilInstallHelp string
)

func init() {
	switch {
	case binaryExists("apt"):
		CertutilInstallHelp = "apt install libnss3-tools"
	case binaryExists("yum"):
		CertutilInstallHelp = "yum install nss-tools"
	case binaryExists("zypper"):
		CertutilInstallHelp = "zypper install mozilla-nss-tools"
	}
	if pathExists("/etc/pki/ca-trust/source/anchors/") {
		SystemTrustFilename = "/etc/pki/ca-trust/source/anchors/%s.pem"
		SystemTrustCommand = []string{"update-ca-trust", "extract"}
	} else if pathExists("/usr/local/share/ca-certificates/") {
		SystemTrustFilename = "/usr/local/share/ca-certificates/%s.crt"
		SystemTrustCommand = []string{"update-ca-certificates"}
	} else if pathExists("/etc/ca-certificates/trust-source/anchors/") {
		SystemTrustFilename = "/etc/ca-certificates/trust-source/anchors/%s.crt"
		SystemTrustCommand = []string{"trust", "extract-compat"}
	} else if pathExists("/usr/share/pki/trust/anchors") {
		SystemTrustFilename = "/usr/share/pki/trust/anchors/%s.pem"
		SystemTrustCommand = []string{"update-ca-certificates"}
	}
}

func (m *MKCert) systemTrustFilename() string {
	return fmt.Sprintf(SystemTrustFilename, strings.Replace(m.caUniqueName(), " ", "_", -1))
}

func (m *MKCert) installPlatform() error {
	if SystemTrustCommand == nil {
		log.Printf("Installing to the system store is not yet supported on this Linux 😣 but %s will still work.", NSSBrowsers)
		log.Printf("You can also manually install the root certificate at %q.", filepath.Join(m.CAROOT, rootName))
		return nil
	}

	cert, err := ioutil.ReadFile(filepath.Join(m.CAROOT, rootName))
	if err != nil {
		return fmt.Errorf("failed to read root certificate: %w", err)
	}

	cmd := commandWithSudo("tee", m.systemTrustFilename())
	cmd.Stdin = bytes.NewReader(cert)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute 'tee' with output %s: %w", out, err)
	}

	cmd = commandWithSudo(SystemTrustCommand...)
	out, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute '%s' with output %s: %w", strings.Join(SystemTrustCommand, " "), out, err)
	}

	return nil
}

func (m *MKCert) uninstallPlatform() error {
	if SystemTrustCommand == nil {
		log.Printf("Uninstalling to the system store is not yet supported on this Linux but %s will still work.", NSSBrowsers)
		return nil
	}

	cmd := commandWithSudo("rm", "-f", m.systemTrustFilename())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute 'rm' with output %s: %w", out, err)
	}

	// We used to install under non-unique filenames.
	legacyFilename := fmt.Sprintf(SystemTrustFilename, "mkcert-rootCA")
	if pathExists(legacyFilename) {
		cmd := commandWithSudo("rm", "-f", legacyFilename)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to execute 'rm (legacy filename)' with output %s: %w", out, err)
		}
	}

	cmd = commandWithSudo(SystemTrustCommand...)
	out, err = cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("failed to execute '%s' with output %s: %w", strings.Join(SystemTrustCommand, " "), out, err)
	}
	return nil
}
