package csvcloud

import "context"

// Event contains only a closed category. Sinks may aggregate counts; there are
// no identifiers, free-form reasons or customer/provider metadata to serialize.
// Before enabling a production sink, its encrypted log group must have <=7-day
// retention and operator-only read access; no stream/export/subscription sink.
type Event uint8

const (
	InitialQuote Event = iota + 1
	Requote
	MalformedPayment
	PaymentRejected
	ProviderVerifyFailure
	ProviderSettleFailure
	PaymentUnknown
	DocumentFailure
	InfrastructureFailure
	PaymentFinalized
)

func (e Event) Name() string {
	switch e {
	case InitialQuote:
		return "initial_quote"
	case Requote:
		return "requote"
	case MalformedPayment:
		return "malformed_payment"
	case PaymentRejected:
		return "payment_rejected"
	case ProviderVerifyFailure:
		return "provider_verify_failure"
	case ProviderSettleFailure:
		return "provider_settle_failure"
	case PaymentUnknown:
		return "payment_unknown"
	case DocumentFailure:
		return "document_failure"
	case InfrastructureFailure:
		return "infrastructure_failure"
	case PaymentFinalized:
		return "payment_finalized"
	default:
		return "unknown"
	}
}

// Initial quotes are expected protocol discovery, never failed payments.
func (e Event) FailedPayment() bool {
	return e == MalformedPayment || e == PaymentRejected || e == ProviderVerifyFailure || e == ProviderSettleFailure
}

type EventSink interface{ Count(context.Context, Event) }

func (s Payments) event(ctx context.Context, e Event) {
	if s.Events != nil {
		s.Events.Count(ctx, e)
	}
}

type EventRecord struct {
	Schema        int    `json:"schema"`
	Event         string `json:"event"`
	Count         int    `json:"count"`
	FailedPayment bool   `json:"failed_payment"`
}

func (e Event) Record() EventRecord {
	return EventRecord{Schema: 1, Event: e.Name(), Count: 1, FailedPayment: e.FailedPayment()}
}
