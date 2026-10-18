package main

import "strings"

// Reviewed 2026-10-12 against OFAC's active geographic programs. The owner
// deliberately chose whole-country exclusions even for targeted programs.
// This is a business access policy, not a list of universally illegal markets.
// Western Balkans: Albania, Bosnia and Herzegovina, Kosovo, Montenegro,
// North Macedonia and Serbia. Entire Ukraine covers its restricted regions.
// Syria remains here for the targeted PAARSS program, not the revoked embargo.
// China is also an explicit owner exclusion; Hong Kong has its own program.
// Sources and the manual review procedure are in OPERATIONS.md.
const geographicPolicyVersion = "2026-10-12-broad-v1"
const geographicCountryCodes = "AF AL BA BY CD CF CN CU HK IR IQ KP LB LY ME MK ML MM NI RS RU SD SO SS SY UA VE XK YE"

func blockedCountries() []string { return strings.Fields(geographicCountryCodes) }

func cloudFrontBlockedCountries() []string {
	codes := blockedCountries()
	result := make([]string, 0, len(codes))
	for _, code := range codes {
		// WAF accepts Kosovo's XK extension; CloudFront's native restriction
		// API rejects it. Kosovo remains blocked by the associated global WAF.
		if code != "XK" {
			result = append(result, code)
		}
	}
	return result
}

func geographicStatement() map[string]any {
	// No ForwardedIPConfig: WAF uses the actual viewer connection, never an
	// attacker-supplied X-Forwarded-For or country header.
	return map[string]any{"geoMatchStatement": map[string]any{"countryCodes": blockedCountries()}}
}
