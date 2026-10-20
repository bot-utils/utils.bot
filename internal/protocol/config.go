package protocol

import (
	"errors"
	"strings"

	x402 "github.com/x402-foundation/x402/go/v2"
	"github.com/x402-foundation/x402/go/v2/types"
)

const (
	ModeMock           = "mock"
	ModeSepolia        = "cdp-base-sepolia"
	ModeBase           = "cdp-base"
	BaseNetwork        = "eip155:8453"
	BaseAsset          = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
	TermsVersion       = "2026-10-19-r12"
	SmallPDFLimit      = 25 << 20
	SmallAmount        = "10000"
	LargeAmount        = "20000"
	PricingDescription = "0.01 USDC for PDFs through 25 MiB; 0.02 USDC above 25 MiB through 100 MiB"
)

// Config is immutable after construction. Its zero value is the existing mock
// configuration, keeping local fixtures separate from explicitly enabled CDP.
type Config struct {
	mode, payTo string
	public      bool
	large       bool
}

func NewConfig(mode, payTo string) (Config, error) {
	if mode == "" {
		mode = ModeMock
	}
	switch mode {
	case ModeMock:
		if payTo != "" && !strings.EqualFold(payTo, PayTo) {
			return Config{}, errors.New("mock receiving address cannot be changed")
		}
		return Config{}, nil
	case ModeSepolia, ModeBase:
		if !Hex(payTo, 20) || strings.EqualFold(payTo, "0x"+strings.Repeat("0", 40)) || strings.EqualFold(payTo, PayTo) {
			return Config{}, errors.New("CDP mode requires an explicit receiving address")
		}
		return Config{mode: mode, payTo: strings.ToLower(payTo)}, nil
	default:
		return Config{}, errors.New("unsupported payment mode")
	}
}

// WithPublicAccess is an explicit launch setting. Public paid access is never
// enabled by a payment-mode change or by a malformed environment value.
func (c Config) WithPublicAccess(setting string) (Config, error) {
	switch setting {
	case "", "0":
		c.public = false
	case "1":
		if c.Mode() != ModeBase {
			return Config{}, errors.New("public access requires Base mainnet mode")
		}
		c.public = true
	default:
		return Config{}, errors.New("public access must be 0 or 1")
	}
	return c, nil
}
func (c Config) PublicAccess() bool { return c.public }

func (c Config) Mode() string {
	if c.mode == "" {
		return ModeMock
	}
	return c.mode
}
func (c Config) Network() string {
	if c.mode == ModeBase {
		return BaseNetwork
	}
	return Network
}
func (c Config) Asset() string {
	if c.mode == ModeBase {
		return BaseAsset
	}
	return Asset
}
func (c Config) PayTo() string {
	if c.mode == "" {
		return PayTo
	}
	return c.payTo
}

// Native Base USDC and the Sepolia test token have different EIP-712 names.
func (c Config) TokenName() string {
	if c.mode == ModeBase {
		return "USD Coin"
	}
	return "USDC"
}

// ForSize selects the exact price from uploaded bytes. Before upload, a length
// is only a quote hint; unknown lengths initially receive the smaller quote.
func (c Config) ForSize(size int64) Config {
	c.large = size > SmallPDFLimit
	return c
}

func (c Config) Requirements() types.PaymentRequirements {
	amount := SmallAmount
	if c.large {
		amount = LargeAmount
	}
	return types.PaymentRequirements{Scheme: "exact", Network: c.Network(), Asset: c.Asset(), Amount: amount, PayTo: c.PayTo(), MaxTimeoutSeconds: 180,
		Extra: map[string]interface{}{"name": c.TokenName(), "version": "2", "assetTransferMethod": "eip3009", "paymentFlow": "authorization"}}
}
func (c Config) Description() string {
	switch c.Mode() {
	case ModeBase:
		return "PDF text extraction. Standard x402 v2 authorization; charge only after successful parsing: " + PricingDescription + " on Base. Parsing failures are not charged."
	case ModeSepolia:
		return "TESTNET PAYMENTS ONLY. PDF text extraction. Coinbase settles Base Sepolia test USDC; no real-value funds. Parsing failures are not charged."
	default:
		return "MOCK PAYMENTS ONLY. PDF text extraction. Parsing failures are not charged."
	}
}
func (c Config) Quote(resource string) types.PaymentRequired {
	terms := WebsiteBase(resource) + "/terms#terms-of-use"
	return types.PaymentRequired{X402Version: 2, Resource: &types.ResourceInfo{URL: resource, MimeType: "application/json", Description: c.Description() + " Limits: 100 MiB upload, up to 100 returned pages and 1 MiB text. The full quoted fee applies to successful partial or blank results. Five failed/unpaid attempts or abandoned verified requests per wallet per fixed one-hour window pause new requests; paid retries also pause after five abandonments of that payment. Honor Retry-After on 429. Submitting a PDF with payment authorization indicates agreement to Terms " + TermsVersion + ": " + terms}, Accepts: []types.PaymentRequirements{c.Requirements()}}
}
func (c Config) ValidSettlement(s *x402.SettleResponse) bool {
	return s != nil && s.Success && s.ErrorReason == "" && s.ErrorMessage == "" && string(s.Network) == c.Network() && Hex(s.Transaction, 32) && Hex(s.Payer, 20) && (s.Amount == "" || s.Amount == c.Requirements().Amount)
}
func (c Config) SettlementEvidence(s *x402.SettleResponse) *x402.SettleResponse {
	if s == nil || string(s.Network) != c.Network() || !Hex(s.Transaction, 32) || !Hex(s.Payer, 20) || (s.Amount != "" && s.Amount != c.Requirements().Amount) {
		return nil
	}
	reason := ""
	if !s.Success {
		reason = "settlement_failed"
		if s.ErrorReason == "settlement_pending" {
			reason = s.ErrorReason
		}
	}
	return &x402.SettleResponse{Success: s.Success, Transaction: s.Transaction, Network: s.Network, Payer: s.Payer, Amount: s.Amount, ErrorReason: reason}
}
