package csvcloud

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func chainFixture(t *testing.T, mode string) (*FinalizedChain, Settlement, *int) {
	t.Helper()
	s := Settlement{Payer: "0x1111111111111111111111111111111111111111", Receiver: "0x2222222222222222222222222222222222222222", Asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", Nonce: "0x" + strings.Repeat("a", 64), Network: "eip155:8453", Amount: "12345", StartBlock: 99, ValidBefore: fixtureTime.Unix() + 180}
	calls := 0
	c, e := NewFinalizedChain("https://mainnet.base.org")
	if e != nil {
		t.Fatal(e)
	}
	hash := "0x" + strings.Repeat("b", 64)
	tx := "0x" + strings.Repeat("c", 64)
	authorization := chainLog{Address: s.Asset, Topics: []string{event("AuthorizationUsed(address,bytes32)"), topic(s.Payer), s.Nonce}, Transaction: tx, BlockHash: hash, BlockNumber: "0x64", Data: "0x"}
	transfer := chainLog{Address: s.Asset, Topics: []string{event("Transfer(address,address,uint256)"), topic(s.Payer), topic(s.Receiver)}, Transaction: tx, BlockHash: hash, BlockNumber: "0x64", Data: fmt.Sprintf("0x%064x", 12345)}
	c.Client = transport(func(req *http.Request) (*http.Response, error) {
		calls++
		raw, _ := io.ReadAll(req.Body)
		var in struct {
			ID     uint64            `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if json.Unmarshal(raw, &in) != nil {
			t.Fatal("request")
		}
		var result any
		switch in.Method {
		case "eth_chainId":
			result = "0x2105"
			if mode == "wrong-chain" {
				result = "0x1"
			}
		case "eth_getBlockByNumber":
			var tag string
			_ = json.Unmarshal(in.Params[0], &tag)
			n := "0x64"
			if mode == "unfinalized" && tag == "finalized" {
				n = "0x63"
			}
			stamp := s.ValidBefore + 1
			if mode == "unused-before" {
				stamp = s.ValidBefore
			}
			b := chainBlock{Number: n, Timestamp: blockTag(stamp), Hash: hash}
			if mode == "reorg" && tag != "finalized" {
				b.Hash = "0x" + strings.Repeat("d", 64)
			}
			result = b
		case "eth_call":
			var stateRef map[string]any
			_ = json.Unmarshal(in.Params[1], &stateRef)
			if stateRef["blockHash"] != hash || stateRef["requireCanonical"] != true {
				t.Fatal("unpinned state")
			}
			result = "0x" + strings.Repeat("0", 63) + "1"
			if strings.HasPrefix(mode, "unused") {
				result = "0x" + strings.Repeat("0", 64)
			}
		case "eth_getLogs":
			result = []chainLog{authorization}
			if mode == "missing" {
				result = []chainLog{}
			}
			if mode == "duplicate-auth" {
				result = []chainLog{authorization, authorization}
			}
		case "eth_getTransactionReceipt":
			logs := []chainLog{authorization, transfer}
			if mode == "wrong-transfer" {
				logs[1].Data = fmt.Sprintf("0x%064x", 12346)
			}
			if mode == "duplicate-transfer" {
				logs = append(logs, transfer)
			}
			result = map[string]any{"transactionHash": tx, "status": "0x1", "blockHash": hash, "blockNumber": "0x64", "logs": logs}
		default:
			t.Fatalf("forbidden RPC method %s", in.Method)
		}
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": in.ID, "result": result})
		return response(200, string(b), nil), nil
	})
	return c, s, &calls
}
func TestFinalizedChainExactEvidenceAndUnknownCases(t *testing.T) {
	for _, mode := range []string{"paid", "wrong-chain", "unfinalized", "reorg", "missing", "duplicate-auth", "wrong-transfer", "duplicate-transfer", "unused-before", "unused-after"} {
		t.Run(mode, func(t *testing.T) {
			c, s, _ := chainFixture(t, mode)
			out, e := c.Lookup(ctx, s)
			switch mode {
			case "paid":
				if e != nil || out.State != "PAID" || out.Transaction == "" {
					t.Fatal(out, e)
				}
			case "unused-after":
				if e != nil || out.State != "UNPAID" {
					t.Fatal(out, e)
				}
			default:
				if out.State != "PAYMENT_UNKNOWN" {
					t.Fatal("released without exact finality", out, e)
				}
			}
		})
	}
}
func TestChainRejectsUntrustedEndpoints(t *testing.T) {
	for _, u := range []string{"https://customer.example", "http://mainnet.base.org", "https://mainnet.base.org.evil.example", "https://mainnet.base.org/?key=x", "https://127.0.0.1", "https://mainnet.base.org/path"} {
		if _, e := NewFinalizedChain(u); e != ErrInvalid {
			t.Fatal("accepted arbitrary RPC", u)
		}
	}
}
