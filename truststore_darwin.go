// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mkcert

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"howett.net/plist"
)

var (
	FirefoxProfiles     = []string{os.Getenv("HOME") + "/Library/Application Support/Firefox/Profiles/*"}
	CertutilInstallHelp = "brew install nss"
	NSSBrowsers         = "Firefox"
)

// https://github.com/golang/go/issues/24652#issuecomment-399826583
var trustSettings []interface{}
var _, _ = plist.Unmarshal(trustSettingsData, &trustSettings)
var trustSettingsData = []byte(`
<array>
	<dict>
		<key>kSecTrustSettingsPolicy</key>
		<data>
		KoZIhvdjZAED
		</data>
		<key>kSecTrustSettingsPolicyName</key>
		<string>sslServer</string>
		<key>kSecTrustSettingsResult</key>
		<integer>1</integer>
	</dict>
	<dict>
		<key>kSecTrustSettingsPolicy</key>
		<data>
		KoZIhvdjZAEC
		</data>
		<key>kSecTrustSettingsPolicyName</key>
		<string>basicX509</string>
		<key>kSecTrustSettingsResult</key>
		<integer>1</integer>
	</dict>
</array>
`)

func (m *MKCert) installPlatform() error {
	cmd := commandWithSudo("security", "add-trusted-cert", "-d", "-k", "/Library/Keychains/System.keychain", filepath.Join(m.CAROOT, rootName))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute 'security add-trusted-cert' with output %s: %w", out, err)
	}

	// Make trustSettings explicit, as older Go does not know the defaults.
	// https://github.com/golang/go/issues/24652

	plistFile, err := ioutil.TempFile("", "trust-settings")
	if err != nil {
		fmt.Errorf("failed to create temp file: %w", err)
	}
	fatalIfErr(err, "failed to create temp file")
	defer os.Remove(plistFile.Name())

	cmd = commandWithSudo("security", "trust-settings-export", "-d", plistFile.Name())
	out, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute 'security trust-settings-export' with output %s: %w", out, err)
	}

	plistData, err := ioutil.ReadFile(plistFile.Name())
	if err != nil {
		fmt.Errorf("failed to read trust settings: %w", err)
	}
	var plistRoot map[string]interface{}
	_, err = plist.Unmarshal(plistData, &plistRoot)
	if err != nil {
		fmt.Errorf("failed to parse trust settings: %w", err)
	}

	rootSubjectASN1, _ := asn1.Marshal(m.caCert.Subject.ToRDNSequence())

	if plistRoot["trustVersion"].(uint64) != 1 {
		return fmt.Errorf("unsupported trust settings version: %d", plistRoot["trustVersion"].(uint64))
	}
	trustList := plistRoot["trustList"].(map[string]interface{})
	for key := range trustList {
		entry := trustList[key].(map[string]interface{})
		if _, ok := entry["issuerName"]; !ok {
			continue
		}
		issuerName := entry["issuerName"].([]byte)
		if !bytes.Equal(rootSubjectASN1, issuerName) {
			continue
		}
		entry["trustSettings"] = trustSettings
		break
	}

	plistData, err = plist.MarshalIndent(plistRoot, plist.XMLFormat, "\t")
	if err != nil {
		fmt.Errorf("failed to serialize trust settings: %w", err)
	}
	if err = ioutil.WriteFile(plistFile.Name(), plistData, 0600); err != nil {
		fmt.Errorf("failed to write trust settings: %w", err)
	}

	cmd = commandWithSudo("security", "trust-settings-import", "-d", plistFile.Name())
	out, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute 'security trust-settings-import' with output %s: %w", out, err)
	}
	return nil
}

func (m *MKCert) uninstallPlatform() error {
	cmd := commandWithSudo("security", "remove-trusted-cert", "-d", filepath.Join(m.CAROOT, rootName))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute 'security remove-trusted-cert' with output %s: %w", out, err)
	}
	return nil
}
