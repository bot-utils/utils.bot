package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"

	x402 "github.com/x402-foundation/x402/go/v2"
	"github.com/x402-foundation/x402/go/v2/types"

	"pdfservice/internal/htmllimits"
)

const (
	MaxHTMLURL              = htmllimits.MaxHTMLURL
	MaxHTMLHostLabels       = htmllimits.MaxHTMLHostLabels
	MaxHTMLRedirects        = htmllimits.MaxHTMLRedirects
	MaxHTMLTokens           = htmllimits.MaxHTMLTokens
	MaxHTMLToken            = htmllimits.MaxHTMLToken
	MaxHTMLTitle            = htmllimits.MaxHTMLTitle
	HTMLFetchSeconds        = htmllimits.HTMLFetchSeconds
	HTMLWorkerSeconds       = htmllimits.HTMLWorkerSeconds
	HTMLRequestSeconds      = htmllimits.HTMLRequestSeconds
	HTMLPath                = htmllimits.HTMLPath
	MaxHTMLRequest          = htmllimits.MaxHTMLRequest
	MaxHTMLSource           = htmllimits.MaxHTMLSource
	MaxMarkdown             = htmllimits.MaxMarkdown
	MaxHTMLResult           = htmllimits.MaxHTMLResult
	FailedParseWindow       = time.Hour
	RequestTimeout          = 90 * time.Second
	MinimumParseBudget      = 45 * time.Second
	MaxPDF                  = 100 << 20
	MaxPaymentHeader        = 24 << 10
	MaxPaymentPayload       = 32 << 10
	MaxOutput               = 5 << 20
	MaxText                 = 1 << 20
	MaxPages                = 100
	Network                 = "eip155:84532" // Mock deployment only: Base Sepolia, never real funds.
	Asset                   = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
	PayTo                   = "0x1111111111111111111111111111111111111111"
	PaymentOutcomeAbandoned = "abandoned"
)

type PaymentRequest struct {
	Tool           string `json:"tool,omitempty"`
	TraceID        string `json:"traceID,omitempty"`
	VerifyOnly     bool   `json:"verifyOnly,omitempty"`
	CheckDocument  bool   `json:"checkDocument,omitempty"`
	DocumentFailed bool   `json:"documentFailed,omitempty"`
	RecordOutcome  string `json:"recordOutcome,omitempty"`
	Header         string `json:"header"`
	BodySHA256     string `json:"bodySHA256"`
	BodyLength     int64  `json:"bodyLength"`
	Deadline       int64  `json:"deadline"`
}

type PaymentResponse struct {
	Pass       bool                 `json:"pass"`
	Status     int                  `json:"status,omitempty"`
	Error      string               `json:"error,omitempty"`
	RetryAfter int64                `json:"retryAfter,omitempty"`
	Settlement *x402.SettleResponse `json:"settlement,omitempty"`
}

func Requirements() types.PaymentRequirements     { return (Config{}).Requirements() }
func Quote(resource string) types.PaymentRequired { return (Config{}).Quote(resource) }

func Header(v any) (string, error) {
	b, err := json.Marshal(v)
	return base64.StdEncoding.EncodeToString(b), err
}
func SHA256(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// ValidSettlement checks the private response contract without doing any crypto.
func ValidSettlement(s *x402.SettleResponse) bool { return (Config{}).ValidSettlement(s) }
func Hex(value string, bytes int) bool {
	if bytes <= 0 || len(value) != 2+bytes*2 || value[:2] != "0x" {
		return false
	}
	_, err := hex.DecodeString(value[2:])
	return err == nil
}

// SettlementEvidence strips unused provider extensions and diagnostic messages.
func SettlementEvidence(s *x402.SettleResponse) *x402.SettleResponse {
	return (Config{}).SettlementEvidence(s)
}
