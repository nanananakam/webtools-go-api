package whois

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// response from APNIC
func TestIP1_1_1_1(t *testing.T) {
	rdapResponseRawString, err := os.ReadFile("./rdapRawResponse1.1.1.1.json")
	if err != nil {
		panic(err)
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
	rdapResponseRawString, err := os.ReadFile("./rdapRawResponse8.8.8.8.json")
	if err != nil {
		panic(err)
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
	rdapResponseRawString, err := os.ReadFile("./rdapRawResponse2.2.2.2.json")
	if err != nil {
		panic(err)
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
	rdapResponseRawString, err := os.ReadFile("./rdapRawResponse196.46.23.70.json")
	if err != nil {
		panic(err)
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
	rdapResponseRawString, err := os.ReadFile("./rdapRawResponse190.120.4.21.json")
	if err != nil {
		panic(err)
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
