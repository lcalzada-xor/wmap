package wps

import (
	"bufio"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestReaverRegex simulates the parsing logic without running the actual command.
func TestReaverRegex(t *testing.T) {
	// Sample Output from Reaver 1.6.6
	sampleOutput := `
[+] Waiting for beacon from 00:11:22:33:44:55
[+] Associated with 00:11:22:33:44:55 (ESSID: TestNetwork)
[+] WPS PIN: '12345670'
[+] WPA PSK: 'secretpassword'
[+] AP SSID: TestNetwork
`

	// Logic copied from wps_engine.go for independent verification
	importReg := func(line string) (string, string) {
		// These must match wps_engine.go exactly
		pinRegex := regexp.MustCompile(`WPS PIN:\s*['"]?([0-9]+)['"]?`)
		pskRegex := regexp.MustCompile(`WPA PSK:\s*['"]?([^'"]+)['"]?`)

		pin := ""
		psk := ""
		if matches := pinRegex.FindStringSubmatch(line); len(matches) > 1 {
			pin = matches[1]
		}
		if matches := pskRegex.FindStringSubmatch(line); len(matches) > 1 {
			psk = matches[1]
		}
		return pin, psk
	}

	scanner := bufio.NewScanner(strings.NewReader(sampleOutput))
	foundPin := ""
	foundPsk := ""

	for scanner.Scan() {
		line := scanner.Text()
		p, k := importReg(line)
		if p != "" {
			foundPin = p
		}
		if k != "" {
			foundPsk = k
		}
	}

	assert.Equal(t, "12345670", foundPin)
	assert.Equal(t, "secretpassword", foundPsk)
}
