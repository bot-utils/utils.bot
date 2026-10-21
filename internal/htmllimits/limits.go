// Package htmllimits holds the data contract without payment or cloud SDK code.
package htmllimits

const (
	MaxHTMLURL         = 8192
	MaxHTMLHostLabels  = 10
	MaxHTMLRedirects   = 4
	MaxHTMLTokens      = 200000
	MaxHTMLToken       = 256 << 10
	MaxHTMLTitle       = 1024
	HTMLFetchSeconds   = 15
	HTMLWorkerSeconds  = 20
	HTMLRequestSeconds = 65
	HTMLPath           = "/v1/html/markdown"
	MaxHTMLRequest     = 16 << 10
	MaxHTMLSource      = 4 << 20
	// The worker returns bounded, uncompressed JSON over private HTTP. This is
	// independent of the smaller ALB-to-controller envelope limit.
	MaxHTMLResult = 4 << 20
	// ALB caps the complete response JSON at 1 MiB. Gzip is base64 encoded
	// internally; reserve room for headers and the maximum settlement receipt.
	ALBMaxResponse     = 1 << 20
	ALBEnvelopeReserve = 4 << 10
	MaxCompressedBody  = (ALBMaxResponse - ALBEnvelopeReserve) / 4 * 3
	// Metadata and JSON escaping consume part of this shared result budget.
	MaxMarkdown   = MaxHTMLResult
	VMMaxJob      = 2 << 20
	VMMaxResponse = MaxHTMLResult
)
