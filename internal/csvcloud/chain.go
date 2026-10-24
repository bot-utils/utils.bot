package csvcloud

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"pdfservice/internal/jsonwire"
	"pdfservice/internal/protocol"
)

type Outcome struct{ State, Transaction string }
type Chain interface {
	Snapshot(context.Context, string) (int64, error)
	Lookup(context.Context, Settlement) (Outcome, error)
}
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// FinalizedChain is read-only: its only RPC methods are chain ID, block, call,
// logs and receipt. It has no transaction-signing or broadcast method.
type FinalizedChain struct {
	endpoint string
	Client   HTTPDoer
	next     atomic.Uint64
}

func (*FinalizedChain) GoString() string { return "CSV finalized-chain reader [redacted]" }
func (*FinalizedChain) String() string   { return "CSV finalized-chain reader [redacted]" }

// NewFinalizedChain accepts only the pinned public Base RPC origin. A dedicated
// provider needs a reviewed source change; no request field can select a host.
func NewFinalizedChain(endpoint string) (*FinalizedChain, error) {
	if endpoint != "https://mainnet.base.org" && endpoint != "https://sepolia.base.org" {
		return nil, ErrInvalid
	}
	return &FinalizedChain{endpoint: endpoint, Client: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 8 * time.Second, MaxConnsPerHost: 2}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *FinalizedChain) rpc(ctx context.Context, method string, params any, out any) error {
	u, err := url.Parse(c.endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || c.Client == nil {
		return ErrUnknown
	}
	id := c.next.Add(1)
	body, _ := json.Marshal(struct {
		Version string `json:"jsonrpc"`
		ID      uint64 `json:"id"`
		Method  string `json:"method"`
		Params  any    `json:"params"`
	}{"2.0", id, method, params})
	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewReader(body))
	if err != nil {
		return ErrUnknown
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.Client.Do(req)
	if err != nil {
		return ErrUnknown
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if err != nil || res.StatusCode != 200 || len(raw) > 1<<20 {
		return ErrUnknown
	}
	var response struct {
		Version string          `json:"jsonrpc"`
		ID      uint64          `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if jsonwire.Unmarshal(raw, &response, 1<<20) != nil || response.Version != "2.0" || response.ID != id || len(response.Error) > 0 && string(response.Error) != "null" || len(response.Result) == 0 || string(response.Result) == "null" || json.Unmarshal(response.Result, out) != nil {
		return ErrUnknown
	}
	return nil
}

type chainBlock struct {
	Number    string `json:"number"`
	Timestamp string `json:"timestamp"`
	Hash      string `json:"hash"`
}
type chainLog struct {
	Address     string   `json:"address"`
	Topics      []string `json:"topics"`
	Data        string   `json:"data"`
	Transaction string   `json:"transactionHash"`
	BlockHash   string   `json:"blockHash"`
	BlockNumber string   `json:"blockNumber"`
	Removed     bool     `json:"removed"`
}

func hexNumber(v string) (int64, error) {
	if !strings.HasPrefix(v, "0x") {
		return 0, ErrUnknown
	}
	n, e := strconv.ParseInt(v[2:], 16, 64)
	if e != nil || n < 0 {
		return 0, ErrUnknown
	}
	return n, nil
}
func blockTag(v int64) string { return "0x" + strconv.FormatInt(v, 16) }
func topic(s string) string {
	return "0x" + strings.Repeat("0", 64-len(strings.TrimPrefix(s, "0x"))) + strings.ToLower(strings.TrimPrefix(s, "0x"))
}
func event(name string) string { return "0x" + fmt.Sprintf("%x", crypto.Keccak256([]byte(name))) }
func (c *FinalizedChain) head(ctx context.Context, network string) (chainBlock, error) {
	var id string
	if c.rpc(ctx, "eth_chainId", []any{}, &id) != nil {
		return chainBlock{}, ErrUnknown
	}
	n, e := hexNumber(id)
	if e != nil || "eip155:"+strconv.FormatInt(n, 10) != network {
		return chainBlock{}, ErrUnknown
	}
	var block chainBlock
	if c.rpc(ctx, "eth_getBlockByNumber", []any{"finalized", false}, &block) != nil || !protocol.Hex(block.Hash, 32) {
		return block, ErrUnknown
	}
	if _, e = hexNumber(block.Number); e != nil {
		return block, e
	}
	if _, e = hexNumber(block.Timestamp); e != nil {
		return block, e
	}
	return block, nil
}
func (c *FinalizedChain) Snapshot(ctx context.Context, network string) (int64, error) {
	b, err := c.head(ctx, network)
	if err != nil {
		return 0, err
	}
	return hexNumber(b.Number)
}
func (c *FinalizedChain) Lookup(ctx context.Context, s Settlement) (Outcome, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	unknown := Outcome{State: "PAYMENT_UNKNOWN"}
	if !protocol.Hex(s.Payer, 20) || !protocol.Hex(s.Receiver, 20) || !protocol.Hex(s.Asset, 20) || !protocol.Hex(s.Nonce, 32) || s.StartBlock < 0 || s.ValidBefore <= 0 {
		return unknown, ErrInvalid
	}
	final, err := c.head(ctx, s.Network)
	if err != nil {
		return unknown, ErrUnknown
	}
	height, _ := hexNumber(final.Number)
	timestamp, _ := hexNumber(final.Timestamp)
	// EIP-1898 pins the state read to this finalized canonical block.
	selector := fmt.Sprintf("%x", crypto.Keccak256([]byte("authorizationState(address,bytes32)"))[:4])
	data := "0x" + selector + strings.TrimPrefix(topic(s.Payer), "0x") + strings.TrimPrefix(s.Nonce, "0x")
	var state string
	if c.rpc(ctx, "eth_call", []any{map[string]string{"to": s.Asset, "data": data}, map[string]any{"blockHash": final.Hash, "requireCanonical": true}}, &state) != nil {
		return unknown, ErrUnknown
	}
	unused := state == "0x"+strings.Repeat("0", 64)
	used := state == "0x"+strings.Repeat("0", 63)+"1"
	if !unused && !used {
		return unknown, ErrUnknown
	}
	canonical := func() bool {
		var current chainBlock
		return c.rpc(ctx, "eth_getBlockByNumber", []any{final.Number, false}, &current) == nil && strings.EqualFold(current.Hash, final.Hash)
	}
	if unused {
		if timestamp > s.ValidBefore && canonical() {
			return Outcome{State: "UNPAID"}, nil
		}
		return unknown, nil
	}
	if s.StartBlock > height || height-s.StartBlock > 65535 {
		return unknown, ErrUnknown
	}
	var matched *chainLog
	for start := s.StartBlock; start <= height; start += 2048 {
		end := min(start+2047, height)
		var logs []chainLog
		if c.rpc(ctx, "eth_getLogs", []any{map[string]any{"address": s.Asset, "fromBlock": blockTag(start), "toBlock": blockTag(end), "topics": []string{event("AuthorizationUsed(address,bytes32)"), topic(s.Payer), strings.ToLower(s.Nonce)}}}, &logs) != nil || len(logs) > 1 {
			return unknown, ErrUnknown
		}
		for _, l := range logs {
			if matched != nil || l.Removed || !strings.EqualFold(l.Address, s.Asset) || len(l.Topics) != 3 || !strings.EqualFold(l.Topics[0], event("AuthorizationUsed(address,bytes32)")) || !strings.EqualFold(l.Topics[1], topic(s.Payer)) || !strings.EqualFold(l.Topics[2], s.Nonce) || !protocol.Hex(l.Transaction, 32) {
				return unknown, ErrUnknown
			}
			copy := l
			matched = &copy
		}
	}
	if matched == nil || s.Transaction != "" && !strings.EqualFold(s.Transaction, matched.Transaction) {
		return unknown, ErrUnknown
	}
	var receipt struct {
		Hash        string     `json:"transactionHash"`
		Status      string     `json:"status"`
		BlockHash   string     `json:"blockHash"`
		BlockNumber string     `json:"blockNumber"`
		Logs        []chainLog `json:"logs"`
	}
	if c.rpc(ctx, "eth_getTransactionReceipt", []any{matched.Transaction}, &receipt) != nil || receipt.Status != "0x1" || !protocol.Hex(receipt.BlockHash, 32) || receipt.BlockNumber != matched.BlockNumber || !strings.EqualFold(receipt.Hash, matched.Transaction) || !strings.EqualFold(receipt.BlockHash, matched.BlockHash) {
		return unknown, ErrUnknown
	}
	number, e := hexNumber(receipt.BlockNumber)
	if e != nil || number < s.StartBlock || number > height {
		return unknown, ErrUnknown
	}
	var actual chainBlock
	if c.rpc(ctx, "eth_getBlockByNumber", []any{receipt.BlockNumber, false}, &actual) != nil || !strings.EqualFold(actual.Hash, receipt.BlockHash) {
		return unknown, ErrUnknown
	}
	transferred, authorized := 0, 0
	allTransfers, allAuthorizations := 0, 0
	for _, l := range receipt.Logs {
		if l.Removed || l.BlockNumber != receipt.BlockNumber || !strings.EqualFold(l.Address, s.Asset) || !strings.EqualFold(l.Transaction, receipt.Hash) || !strings.EqualFold(l.BlockHash, receipt.BlockHash) {
			continue
		}
		if len(l.Topics) == 3 && strings.EqualFold(l.Topics[1], topic(s.Payer)) {
			if strings.EqualFold(l.Topics[0], event("AuthorizationUsed(address,bytes32)")) {
				allAuthorizations++
			}
			if strings.EqualFold(l.Topics[0], event("Transfer(address,address,uint256)")) {
				allTransfers++
			}
		}
		if len(l.Topics) == 3 && strings.EqualFold(l.Topics[0], event("AuthorizationUsed(address,bytes32)")) && strings.EqualFold(l.Topics[1], topic(s.Payer)) && strings.EqualFold(l.Topics[2], s.Nonce) {
			authorized++
		}
		if len(l.Topics) == 3 && strings.EqualFold(l.Topics[0], event("Transfer(address,address,uint256)")) && strings.EqualFold(l.Topics[1], topic(s.Payer)) && strings.EqualFold(l.Topics[2], topic(s.Receiver)) {
			value, ok := newBig(l.Data)
			if ok && value == s.Amount {
				transferred++
			}
		}
	}
	if authorized != 1 || transferred != 1 || allTransfers != 1 || allAuthorizations != 1 || !canonical() {
		return unknown, ErrUnknown
	}
	return Outcome{State: "PAID", Transaction: strings.ToLower(receipt.Hash)}, nil
}

func newBig(v string) (string, bool) {
	if len(v) != 66 || !strings.HasPrefix(v, "0x") {
		return "", false
	}
	n, ok := new(big.Int).SetString(v[2:], 16)
	if !ok {
		return "", false
	}
	return n.String(), true
}
