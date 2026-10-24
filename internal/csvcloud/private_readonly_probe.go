package csvcloud

import (
	"context"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"pdfservice/internal/csvwire"
)

// NewPrivateAWSReadOnlyProbe retains private IP/key authentication, but exposes
// only validation of an existing expired synthetic upload's stored metadata.
// It never creates grants, reads S3, writes metadata, queues, dispatches or pays.
func NewPrivateAWSReadOnlyProbe(raw []byte, cfg aws.Config) (http.Handler, error) {
	handler, err := NewPrivateAWSHTTP(raw, cfg)
	if err != nil {
		return nil, err
	}
	gateway, ok := handler.(PrivateHTTP)
	if !ok {
		return nil, ErrInvalid
	}
	runs, ok := gateway.Backend.(PrivateBackendSet)
	if !ok {
		return nil, ErrInvalid
	}
	gateway.Backend = privateReadOnlyProbe{runs: runs}
	return gateway, nil
}

type privateReadOnlyProbe struct{ runs PrivateBackendSet }

func (p privateReadOnlyProbe) Begin(context.Context, csvwire.Request) (PrivateAdmission, error) {
	return PrivateAdmission{}, ErrDisabled
}
func (p privateReadOnlyProbe) Complete(context.Context, string) error        { return ErrDisabled }
func (p privateReadOnlyProbe) SimulatePayment(context.Context, string) error { return ErrDisabled }
func (p privateReadOnlyProbe) Download(context.Context, string) (PrivateDownload, error) {
	return PrivateDownload{}, ErrDisabled
}
func (p privateReadOnlyProbe) Cancel(context.Context, string) error { return ErrDisabled }
func (p privateReadOnlyProbe) Status(ctx context.Context, id string) (PrivateStatus, error) {
	b, err := p.runs.selectRun(id)
	if err != nil {
		return PrivateStatus{}, err
	}
	job, err := b.job(ctx, id)
	if err != nil {
		privateDependencyFailure("admission_read", err)
		return PrivateStatus{}, err
	}
	if job.Artifact != "UPLOAD_INCOMPLETE" || job.Financial != "UNPAID" || job.Dispatch != nil || job.Settlement != nil || job.UploadUntil > b.now() {
		return PrivateStatus{}, ErrConflict
	}
	for _, object := range job.Inputs {
		if _, err := b.upload(ctx, object); err != nil {
			privateDependencyFailure("admission_upload_metadata", err)
			return PrivateStatus{}, err
		}
	}
	return PrivateStatus{JobID: id, State: "UPLOAD_METADATA_VERIFIED", Financial: "UNPAID", PaymentMode: "synthetic-no-funds"}, nil
}
