package docs

import (
	"strings"

	"pdfservice/internal/protocol"
)

func paymentCopy(cfg protocol.Config) (status, details, availability string) {
	switch cfg.Mode() {
	case protocol.ModeBase:
		if cfg.PublicAccess() {
			return "USDC payments on Base", "Coinbase settles the quoted size-based fee on Base after successful parsing and response preparation: " + protocol.PricingDescription + ". Parsing failures are not charged.", "The public API accepts USDC on Base, subject to geographic, rate and capacity limits."
		}
		return "Private testing · USDC payments on Base", "PDF POST access is currently restricted to the operator. Coinbase settles the quoted size-based fee on Base after successful parsing and response preparation: " + protocol.PricingDescription + ". Parsing failures are not charged.", "PDF POST access remains private during payment validation. The configured path accepts USDC on Base; public launch has not occurred."
	case protocol.ModeSepolia:
		return "Private testing · Base Sepolia test USDC", "PDF POST access is currently restricted to the operator. Coinbase settles Base Sepolia test USDC; test tokens have no real value.", "PDF POST access remains private during testnet validation. Mainnet payments are not accepted in this mode."
	default:
		return "Private testing · mock payments · no real funds move", "PDF POST access is currently restricted to the operator, and payment settlement is mocked on Base Sepolia.", "Documentation is provided for developers and agents. PDF POST access is currently restricted during mock-payment testing. Real payment acceptance is not yet available."
	}
}

// Every representation is derived from this same trusted deployment config.
func configurePaymentSpec(spec map[string]any, cfg protocol.Config) {
	if cfg.Mode() == protocol.ModeMock {
		return
	}
	_, details, _ := paymentCopy(cfg)
	terms := spec["x-service-policies"].([]any)
	for _, item := range terms {
		p := item.(map[string]any)
		d := p["description"].(string)
		if strings.HasPrefix(d, "MOCK PAYMENTS ONLY.") {
			d = cfg.Description() + " " + details + " The current API accepts 65-byte EIP-3009 signatures from externally owned EVM accounts; smart-contract wallets and Permit2 are unsupported."
		}
		d = strings.ReplaceAll(d, " In the current mock mode no real funds are charged.", "")
		d = strings.ReplaceAll(d, "mock-payment testing", "payment validation")
		p["description"] = d
	}
	var visit func(any)
	visit = func(v any) {
		switch node := v.(type) {
		case map[string]any:
			if values, ok := node["enum"].([]any); ok && len(values) == 1 && values[0] == "mock" {
				node["enum"] = []string{cfg.Mode()}
			}
			for key, child := range node {
				if key == "paymentMode" {
					if schema, ok := child.(map[string]any); ok {
						schema["enum"] = []string{cfg.Mode()}
					}
				}
				if key == "example" && child == protocol.Network {
					node[key] = cfg.Network()
				}
				if key == "description" && child == "Integer token base units; test USDC has six decimals." {
					node[key] = "Integer token base units; USDC has six decimals."
				}
				visit(child)
			}
		case []any:
			for _, child := range node {
				visit(child)
			}
		}
	}
	visit(spec)
}
