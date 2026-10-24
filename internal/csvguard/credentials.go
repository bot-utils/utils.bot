package transformguard

import (
	"os"
	"strings"
)

// NoCredentials rejects unexpected AWS credential/configuration sources and
// transport secrets. ECS injects three non-secret runtime metadata variables;
// accept only their exact values for this private Fargate profile. The parser
// and transport still clear the environment before handling any input.
func NoCredentials() bool { return credentialFree(os.Environ()) }

func credentialFree(environment []string) bool {
	for _, e := range environment {
		k, v, _ := strings.Cut(e, "=")
		if v == "" {
			continue
		}
		switch k {
		case "AWS_EXECUTION_ENV":
			if v != "AWS_ECS_FARGATE" {
				return false
			}
		case "AWS_REGION", "AWS_DEFAULT_REGION":
			if v != "us-east-2" {
				return false
			}
		default:
			if strings.HasPrefix(k, "AWS_") || k == "CSV_TLS_BOOTSTRAP" {
				return false
			}
		}
	}
	return true
}
