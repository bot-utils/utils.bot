package csvcloud

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/x402-foundation/x402/go/v2/mechanisms/evm"
	"github.com/x402-foundation/x402/go/v2/types"
	"pdfservice/internal/protocol"
)

// SignBound is the supported custom-nonce adapter for the official x402 signer
// interface. It signs only; it cannot submit transactions or transfer funds.
// The caller must validate/trust cfg and q from its authenticated server response.
// Generic exact-scheme clients that select a random nonce are incompatible.
func SignBound(ctx context.Context, signer evm.ClientEvmSigner, cfg protocol.Config, q Quote, now time.Time) (string, error) {
	if signer == nil || cfg.Mode() == protocol.ModeMock || !validAmount(q.Amount) || q.Network != cfg.Network() || !strings.EqualFold(q.Asset, cfg.Asset()) || !strings.EqualFold(q.Receiver, cfg.PayTo()) || !protocol.Hex(q.Nonce, 32) || q.Expires <= now.Unix() || q.Expires > now.Unix()+180 || !protocol.Hex(signer.Address(), 20) || q.Owner != "" && !strings.EqualFold(signer.Address(), q.Owner) {
		return "", ErrInvalid
	}
	chain, ok := new(big.Int).SetString(strings.TrimPrefix(q.Network, "eip155:"), 10)
	if !ok {
		return "", ErrInvalid
	}
	amount, _ := new(big.Int).SetString(q.Amount, 10)
	nonce, _ := hex.DecodeString(strings.TrimPrefix(q.Nonce, "0x"))
	a := evm.ExactEIP3009Authorization{From: signer.Address(), To: q.Receiver, Value: q.Amount, ValidAfter: strconv.FormatInt(now.Unix()-1, 10), ValidBefore: strconv.FormatInt(q.Expires, 10), Nonce: q.Nonce}
	fields := map[string][]evm.TypedDataField{
		"EIP712Domain":              {{Name: "name", Type: "string"}, {Name: "version", Type: "string"}, {Name: "chainId", Type: "uint256"}, {Name: "verifyingContract", Type: "address"}},
		"TransferWithAuthorization": {{Name: "from", Type: "address"}, {Name: "to", Type: "address"}, {Name: "value", Type: "uint256"}, {Name: "validAfter", Type: "uint256"}, {Name: "validBefore", Type: "uint256"}, {Name: "nonce", Type: "bytes32"}},
	}
	sig, err := signer.SignTypedData(ctx, evm.TypedDataDomain{Name: cfg.TokenName(), Version: "2", ChainID: chain, VerifyingContract: q.Asset}, fields, "TransferWithAuthorization", map[string]interface{}{"from": a.From, "to": a.To, "value": amount, "validAfter": big.NewInt(now.Unix() - 1), "validBefore": big.NewInt(q.Expires), "nonce": nonce})
	if err != nil || len(sig) != 65 {
		return "", ErrInvalid
	}
	want := q.Required(cfg)
	rawPayload, _ := json.Marshal(evm.ExactEIP3009Payload{Signature: "0x" + hex.EncodeToString(sig), Authorization: a})
	var payload map[string]interface{}
	_ = json.Unmarshal(rawPayload, &payload)
	p := types.PaymentPayload{X402Version: 2, Resource: want.Resource, Accepted: want.Accepts[0], Extensions: want.Extensions, Payload: payload}
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > protocol.MaxPaymentHeader*3/4 {
		return "", ErrInvalid
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}
