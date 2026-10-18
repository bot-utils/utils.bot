package main

import (
	"net/mail"
	"os"
	"regexp"
	"strings"
)

var accountPattern = regexp.MustCompile(`^[0-9]{12}$`)

func requireDeploymentAccount(account string, local bool) {
	if local {
		if account != "000000000000" {
			panic("LocalStack requires the dummy account")
		}
		return
	}
	expected := os.Getenv("PDF_DEPLOY_ACCOUNT_ID")
	if !accountPattern.MatchString(expected) || expected == "000000000000" || account != expected {
		panic("AWS account must match explicit PDF_DEPLOY_ACCOUNT_ID")
	}
}

func alertEmail() string {
	value := os.Getenv("PDF_ALERT_EMAIL")
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address != value || strings.ContainsAny(value, "\r\n") {
		panic("set PDF_ALERT_EMAIL to the approved notification address")
	}
	return value
}

func hostedZoneID() string {
	value := os.Getenv("PDF_HOSTED_ZONE_ID")
	if !regexp.MustCompile(`^Z[A-Z0-9]{5,}$`).MatchString(value) {
		panic("set PDF_HOSTED_ZONE_ID to the intended domain hosted zone")
	}
	return value
}
