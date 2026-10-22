package csvcloud

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/aws"
	d "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"regexp"
	"strings"
	"time"
)

// ControllerConfig is private synthetic runtime metadata, never a public request.
// A durable run ledger must preserve these exact original task bindings across
// controller restart; recovery never derives replacement task identities.
type ControllerConfig struct {
	RunID, JobID, Account, Table, Bucket, PolicyHash string
	Subnet, SecurityGroup                            string
	Worker, Broker                                   StoppedObserver
	SyntheticOnly                                    bool
}
type Controller struct {
	Config   ControllerConfig
	Repo     Repository
	Channel  NetworkChannel
	Reaper   Reaper
	Fence    RunFence
	Verifier VerifierProcess
}

func AssembleController(ctx context.Context, c ControllerConfig, data aws.Config, verifier VerifierProcess) (Controller, error) {
	if c.Subnet != privateTrialSubnet || c.SecurityGroup != privateTrialSecurityGroup || !c.SyntheticOnly || !opaque(c.RunID) || !opaque(c.JobID) || !regexp.MustCompile(`^[0-9]{12}$`).MatchString(c.Account) || c.Table != "utils-bot-csv-private-"+c.RunID[:16] || c.Bucket != "utils-csv-"+c.Account+"-"+c.RunID[:24] || c.PolicyHash != AbsentBucketPolicyHash || verifier.RunID != c.RunID || verifier.JobID != c.JobID || len(verifier.Key) != ed25519.PrivateKeySize {
		return Controller{}, ErrInvalid
	}
	cluster := "arn:aws:ecs:us-east-2:" + c.Account + ":cluster/utils-bot-csv-trial"
	family := "arn:aws:ecs:us-east-2:" + c.Account + ":task-definition/utils-bot-csv-private-" + c.RunID[:16]
	for kind, s := range map[string]StoppedObserver{"worker": c.Worker, "broker": c.Broker} {
		if kind == "broker" && s.TaskARN == "" {
			continue
		}
		if s.Cluster != cluster || !strings.HasPrefix(s.TaskARN, "arn:aws:ecs:us-east-2:"+c.Account+":task/utils-bot-csv-trial/") || !regexp.MustCompile("^"+family+"-"+kind+`:[1-9][0-9]*$`).MatchString(s.Definition) {
			return Controller{}, ErrInvalid
		}
	}
	a, e := clients(data)
	if e != nil {
		return Controller{}, e
	}
	repo := Repository{Client: a.Dynamo, Table: c.Table, Gate: Gate{Enabled: true}}
	job, e := repo.Get(ctx, c.JobID)
	if e != nil || job == nil || job.Dispatch == nil || job.Dispatch.TaskARN != c.Worker.TaskARN || c.Worker.StartedBy != job.Dispatch.Token[:32] || c.Worker.Group != "csv-"+job.Dispatch.Token || (c.Broker.TaskARN != "" && (c.Broker.StartedBy != c.RunID[:32] || c.Broker.Group != "csv-broker-"+c.RunID)) {
		return Controller{}, ErrInvalid
	}
	brokerRow, e := repo.get(ctx, "BROKER/"+c.RunID)
	if e != nil {
		return Controller{}, e
	}
	if c.Broker.TaskARN != "" {
		arn, aok := brokerRow["task_arn"].(*d.AttributeValueMemberS)
		definition, dok := brokerRow["definition"].(*d.AttributeValueMemberS)
		token, tok := brokerRow["token"].(*d.AttributeValueMemberS)
		if !aok || !dok || !tok || arn.Value != c.Broker.TaskARN || definition.Value != c.Broker.Definition || token.Value != c.RunID || validateBrokerBinding(brokerRow, c) != nil {
			return Controller{}, ErrConflict
		}
	} else if len(brokerRow) != 0 {
		state, ok := brokerRow["state"].(*d.AttributeValueMemberS)
		if !ok || state.Value != "NEVER_STARTED" {
			return Controller{}, ErrUnknown
		}
	}

	prove := func(ctx context.Context, scope StoppedObserver, ids []string) error {
		now := time.Now()
		binding := NetworkBinding{RunID: c.RunID, JobID: c.JobID, TaskARN: scope.TaskARN, Nonce: ID(), Interfaces: ids, Issued: now.Unix(), Expires: now.Add(30 * time.Second).Unix()}
		_, e := verifier.Proof(ctx, scope, binding)
		return e
	}
	stopper := RunStopper{Client: a.ECS, Worker: c.Worker, Broker: c.Broker, Verify: prove, BrokerNeverStarted: func(ctx context.Context) error {
		pk := "BROKER/" + c.RunID
		row, e := repo.get(ctx, pk)
		if e != nil {
			return e
		}
		if len(row) != 0 {
			state, ok := row["state"].(*d.AttributeValueMemberS)
			token, tok := row["token"].(*d.AttributeValueMemberS)
			if ok && tok && state.Value == "NEVER_STARTED" && token.Value == c.RunID {
				return nil
			}
			return ErrUnknown
		}
		return repo.txn(ctx, []d.TransactWriteItem{{Put: &d.Put{TableName: aws.String(repo.Table), Item: map[string]d.AttributeValue{"pk": str(pk), "state": str("NEVER_STARTED"), "token": str(c.RunID), "job": str(c.JobID)}, ConditionExpression: aws.String("attribute_not_exists(pk)")}}})
	}}
	objects := Storage{Client: a.S3, Bucket: c.Bucket, Account: c.Account, Gate: Gate{Enabled: true}}
	fence := RunFence{Repo: repo, Storage: objects, Control: a.S3, RunID: c.RunID, JobID: c.JobID, PolicyHash: c.PolicyHash, SyntheticOnly: true, StopWriters: stopper.Stop, VerifyBucket: func(ctx context.Context) error { return verifier.VerifyBucket(ctx, c.Bucket, c.Account) }}

	channel := NetworkChannel{Repo: repo, RunID: c.RunID, JobID: c.JobID, TaskARN: c.Worker.TaskARN, PublicKey: verifier.Key.Public().(ed25519.PublicKey)}
	reaper := Reaper{Repo: repo, RunID: c.RunID, JobID: c.JobID}
	controller := Controller{Config: c, Repo: repo, Channel: channel, Reaper: reaper, Fence: fence, Verifier: verifier}
	controller.Reaper.Recover = controller.Recover
	return controller, nil
}

// FulfilNetwork services only this run's pinned broker request. It never accepts
// a caller-supplied task ID, URL, proof assertion, filesystem path or code.
func (c Controller) FulfilNetwork(ctx context.Context) error {
	binding, e := c.Channel.Pending(ctx)
	if e != nil {
		return e
	}
	proof, e := c.Verifier.Proof(ctx, c.Config.Worker, binding)
	if e != nil {
		return e
	}
	return c.Channel.Deliver(ctx, proof)
}

// ArmRecovery persists the due time before broker processing. The scheduler
// target calls Tick; duplicates cannot bypass the durable reservation/lease.
func (c Controller) ArmRecovery(ctx context.Context) error {
	if existing, e := c.Reaper.read(ctx); e == nil && existing.RunID == c.Config.RunID {
		return nil
	}
	return c.Reaper.Schedule(ctx, time.Now().Add(2*time.Minute).Unix())
}

// Recover fences publication by versioned DELETING before attempting any
// external cleanup. This is a state reservation, not a false shutdown assertion.
// Cleanup independently proves BOTH original tasks/ENIs and storage are gone.
func (c Controller) Recover(ctx context.Context, id string) error {
	if id != c.Config.JobID {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if terminal, e := c.Repo.Get(ctx, id); e == nil && terminal != nil && terminal.Artifact == "ERASED" {
		return nil
	}
	record, e := c.Reaper.read(ctx)
	if e != nil {
		return e
	}
	claim, ok := ctx.Value(recoveryLeaseKey{}).(recoveryLease)
	if !ok || record.State != "RECOVERING" || record.Version != claim.Version || record.LeaseToken != claim.Token || record.Attempts < 1 || record.Attempts > 3 || c.Reaper.now() >= record.LeaseUntil {
		return ErrConflict
	}
	now := c.Reaper.now()
	if now < record.NotBefore {
		return ErrConflict
	}
	j, e := c.Repo.Get(ctx, id)
	if e != nil || j == nil {
		return ErrUnknown
	}
	if j.Artifact == "ERASED" {
		return nil
	}
	if (j.Financial != "UNPAID" && !(j.Artifact == "DELETING" && j.Financial == "AWAITING_PAYMENT" && j.Settlement == nil)) || j.Dispatch == nil || j.Dispatch.TaskARN != c.Config.Worker.TaskARN || j.TransferStarted && now < j.TransferUntil {
		return ErrConflict
	}
	if j.Artifact != "RUNNING" && j.Artifact != "PROCESSING_UNKNOWN" && j.Artifact != "DELETING" {
		return ErrConflict
	}
	if j.Artifact != "DELETING" {
		n := copyJob(*j)
		n.Version++
		n.Artifact = "DELETING"
		if e = c.Repo.Replace(ctx, *j, n); e != nil {
			return e
		}
	}
	cleanup := Cleanup{Repo: c.Repo, Writers: c.Fence, Objects: c.Fence, Gate: Gate{Enabled: true}}
	return cleanup.Complete(ctx, id)
}

// FinishSynthetic retires an unfunded fixture after its result was independently
// checked. It cannot cancel or erase a pending/unknown/paid settlement.
func (c Controller) FinishSynthetic(ctx context.Context) error {
	if !c.Config.SyntheticOnly {
		return ErrDisabled
	}
	j, e := c.Repo.Get(ctx, c.Config.JobID)
	if e != nil || j == nil {
		return ErrUnknown
	}
	if j.Artifact == "ERASED" || j.Artifact == "DELETING" {
		return nil
	}
	if j.Artifact != "RESULT_PREPARED" || j.Financial != "AWAITING_PAYMENT" || j.Settlement != nil {
		return ErrConflict
	}
	n := copyJob(*j)
	n.Version++
	n.Artifact = "DELETING"
	return c.Repo.Replace(ctx, *j, n)
}

// validateBrokerBinding rejects controller restart metadata that does not match
// the original durable request, even when the caller knows the task ARN.
func validateBrokerBinding(row map[string]d.AttributeValue, c ControllerConfig) error {
	get := func(k string) string {
		v, ok := row[k].(*d.AttributeValueMemberS)
		if !ok {
			return ""
		}
		return v.Value
	}
	if get("job") != c.JobID || get("token") != c.RunID || get("definition") != c.Broker.Definition || !opaque(get("definition_hash")) || get("subnet") != privateTrialSubnet || get("security_group") != privateTrialSecurityGroup || c.Subnet != privateTrialSubnet || c.SecurityGroup != privateTrialSecurityGroup {
		return ErrConflict
	}
	plan := RunPlan{RunID: c.RunID, JobID: c.JobID, Account: c.Account}
	raw, _ := json.Marshal(plan.brokerRequest(get("definition"), get("subnet"), get("security_group")))
	if get("parameters") != Hash(raw) {
		return ErrConflict
	}
	return nil
}
