package whois

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// response from APNIC
func TestIP1_1_1_1(t *testing.T) {
	if _, err := getIp2Location("1.1.1.1"); err != nil {
		t.Error(err)
	}
	if _, err := getGeoIp2Location("1.1.1.1"); err != nil {
		t.Error(err)
	}

	dir, _ := os.Getwd()
	rdapResponseRawString, err := os.ReadFile(dir + "/rdapRawResponse1.1.1.1.json")
	if err != nil {
		t.Error(err)
	}

	var rdapResponse rdapResponse
	if err := json.Unmarshal(rdapResponseRawString, &rdapResponse); err != nil {
		t.Error(err)
	}

	guessNameByRdap := guessNameByRdap(rdapResponse)

	expectedGuessNameByRdapArray := []string{
		"APNIC and Cloudflare DNS Resolver project",
		"Routed globally by AS13335/Cloudflare",
		"Research prefix for APNIC Labs",
	}
	expectedGuessNameByRdap := strings.Join(expectedGuessNameByRdapArray, "\n")

	if guessNameByRdap != expectedGuessNameByRdap {
		t.Errorf("actual: %s, expected: %s", guessNameByRdap, expectedGuessNameByRdap)
	}
}

// response from ARIN
func TestIP8_8_8_8(t *testing.T) {
	if _, err := getIp2Location("8.8.8.8"); err != nil {
		t.Error(err)
	}
	if _, err := getGeoIp2Location("8.8.8.8"); err != nil {
		t.Error(err)
	}

	dir, _ := os.Getwd()
	rdapResponseRawString, err := os.ReadFile(dir + "/rdapRawResponse8.8.8.8.json")
	if err != nil {
		t.Error(err)
	}

	var rdapResponse rdapResponse
	if err := json.Unmarshal(rdapResponseRawString, &rdapResponse); err != nil {
		t.Error(err)
	}

	guessNameByRdap := guessNameByRdap(rdapResponse)

	expectedGuessNameByRdap := "Google LLC"

	if guessNameByRdap != expectedGuessNameByRdap {
		t.Errorf("actual: %s, expected: %s", guessNameByRdap, expectedGuessNameByRdap)
	}
}

// response from RIPE
func TestIP2_2_2_2(t *testing.T) {
	if _, err := getIp2Location("2.2.2.2"); err != nil {
		t.Error(err)
	}
	if _, err := getGeoIp2Location("2.2.2.2"); err != nil {
		t.Error(err)
	}

	dir, _ := os.Getwd()
	rdapResponseRawString, err := os.ReadFile(dir + "/rdapRawResponse2.2.2.2.json")
	if err != nil {
		t.Error(err)
	}

	var rdapResponse rdapResponse
	if err := json.Unmarshal(rdapResponseRawString, &rdapResponse); err != nil {
		t.Error(err)
	}

	guessNameByRdap := guessNameByRdap(rdapResponse)

	expectedGuessNameByRdap := "Gestion des Adresse IP France Telecom"

	if guessNameByRdap != expectedGuessNameByRdap {
		t.Errorf("actual: %s, expected: %s", guessNameByRdap, expectedGuessNameByRdap)
	}
}

// response from AFRINIC
// AFRINICは担当者個人名？が取れてしまうが組織名らしき文字列は無いしそういうものらしい
func TestIP196_46_23_70(t *testing.T) {
	if _, err := getIp2Location("196.46.23.70"); err != nil {
		t.Error(err)
	}
	if _, err := getGeoIp2Location("196.46.23.70"); err != nil {
		t.Error(err)
	}

	dir, _ := os.Getwd()
	rdapResponseRawString, err := os.ReadFile(dir + "/rdapRawResponse196.46.23.70.json")
	if err != nil {
		t.Error(err)
	}

	var rdapResponse rdapResponse
	if err := json.Unmarshal(rdapResponseRawString, &rdapResponse); err != nil {
		t.Error(err)
	}

	guessNameByRdap := guessNameByRdap(rdapResponse)

	expectedGuessNameByRdap := "Martin Bosch"

	if guessNameByRdap != expectedGuessNameByRdap {
		t.Errorf("actual: %s, expected: %s", guessNameByRdap, expectedGuessNameByRdap)
	}
}

// response from LACNIC
func TestIp190_120_4_21(t *testing.T) {
	if _, err := getIp2Location("190.120.4.21"); err != nil {
		t.Error(err)
	}
	if _, err := getGeoIp2Location("190.120.4.21"); err != nil {
		t.Error(err)
	}

	dir, _ := os.Getwd()
	rdapResponseRawString, err := os.ReadFile(dir + "/rdapRawResponse190.120.4.21.json")
	if err != nil {
		t.Error(err)
	}

	var rdapResponse rdapResponse
	if err := json.Unmarshal(rdapResponseRawString, &rdapResponse); err != nil {
		t.Error(err)
	}

	guessNameByRdap := guessNameByRdap(rdapResponse)

	expectedGuessNameByRdap := "Presidencia de la República"

	if guessNameByRdap != expectedGuessNameByRdap {
		t.Errorf("actual: %s, expected: %s", guessNameByRdap, expectedGuessNameByRdap)
	}
}

// rdap以外でIPv6がエラーにならないか確認
func TestIpV6(t *testing.T) {
	if _, err := getIp2Location("2606:4700:4700::1111"); err != nil {
		t.Error(err)
	}
	if _, err := getGeoIp2Location("2606:4700:4700::1111"); err != nil {
		t.Error(err)
	}
}
