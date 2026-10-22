package csvcloud

import (
	"context"
	"time"
)

// Artifacts is the trusted controller boundary between object verification and
// publishing durable job state. No customer event may directly set these states.
type InputVerifier interface {
	VerifyInput(context.Context, Object) (Object, error)
}
type Artifacts struct {
	Repo    Repository
	Inputs  InputVerifier
	Results ResultVerifier
	Gate    Gate
	Now     func() time.Time
}

func (a Artifacts) AcceptUploads(ctx context.Context, id string) error {
	if !a.Gate.Enabled {
		return ErrDisabled
	}
	j, e := a.Repo.Get(ctx, id)
	if e != nil || j == nil {
		return ErrConflict
	}
	if j.Artifact != "UPLOAD_INCOMPLETE" || len(j.Inputs) < 1 || j.UploadUntil <= a.now() {
		return ErrConflict
	}
	n := copyJob(*j)
	for i, o := range n.Inputs {
		v, e := a.Inputs.VerifyInput(ctx, o)
		if e != nil {
			return e
		}
		n.Inputs[i] = v
	}
	n.Version++
	n.Artifact = "UPLOAD_VERIFIED"
	return a.Repo.Replace(ctx, *j, n)
}
func (a Artifacts) PublishResult(ctx context.Context, id, dispatchToken string, m Manifest, until int64) error {
	if !a.Gate.Enabled {
		return ErrDisabled
	}
	j, e := a.Repo.Get(ctx, id)
	if e != nil || j == nil {
		return ErrConflict
	}
	if j.Artifact != "RUNNING" || j.Dispatch == nil || j.Dispatch.Token != dispatchToken || j.Dispatch.State != "ACTIVE" || j.Result != nil || !m.Valid() || m.Object.JobID != id || until <= a.now() || until > a.now()+1800 {
		return ErrConflict
	}
	verified, e := a.Results.VerifyResult(ctx, m)
	if e != nil {
		return e
	}
	n := copyJob(*j)
	n.Version++
	n.Artifact = "RESULT_PREPARED"
	n.Financial = "AWAITING_PAYMENT"
	n.Result = &verified
	n.ResultUntil = until
	return a.Repo.Replace(ctx, *j, n)
}

func (a Artifacts) now() int64 {
	if a.Now != nil {
		return a.Now().Unix()
	}
	return time.Now().Unix()
}
