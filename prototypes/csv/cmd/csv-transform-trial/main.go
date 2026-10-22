// Synthetic transform validation only. No customer files, SDK or payment path.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"utils.bot/csvprototype/internal/tabular"
	"utils.bot/csvprototype/internal/transformguard"
)

var samples = []struct{ raw, trim, lower, upper, replace string }{
	{"  HeLLo  ", "HeLLo", "  hello  ", "  HELLO  ", "  HeLLo  "},
	{"\t\u00a0ÉΣİß\u2003", "ÉΣİß", "\t\u00a0éσiß\u2003", "\t\u00a0ÉΣİß\u2003", "\t\u00a0ÉΣİß\u2003"},
	{"aaa,$1\nx", "aaa,$1\nx", "aaa,$1\nx", "AAA,$1\nX", "$1\\a,$1\nx"},
	{"", "", "", "", ""},
	{"\u200b=SUM(A1:A2)\ufeff", "\u200b=SUM(A1:A2)\ufeff", "\u200b=sum(a1:a2)\ufeff", "\u200b=SUM(A1:A2)\ufeff", "\u200b=SUM(A1:A2)\ufeff"},
	{"$(curl forbidden.invalid)", "$(curl forbidden.invalid)", "$(curl forbidden.invalid)", "$(CURL FORBIDDEN.INVALID)", "$(curl forbidden.invalid)"},
	{"ȿ", "ȿ", "ȿ", "Ȿ", "ȿ"},
	{"e\u0301", "e\u0301", "e\u0301", "E\u0301", "e\u0301"},
}

type metrics struct {
	ProcessPeakRSSBytes int64   `json:"process_peak_rss_bytes"`
	Status              string  `json:"status"`
	Operation           string  `json:"operation"`
	MiB                 int     `json:"mib"`
	Rows                int     `json:"rows"`
	InputBytes          int64   `json:"input_bytes"`
	LogicalBytes        int64   `json:"logical_bytes"`
	EncodedBytes        int64   `json:"encoded_bytes"`
	LogicalHash         string  `json:"logical_sha256"`
	EncodedHash         string  `json:"encoded_sha256"`
	FixtureSeconds      float64 `json:"fixture_seconds"`
	WorkerSeconds       float64 `json:"worker_seconds"`
	VerifySeconds       float64 `json:"verification_seconds"`
	Scope               string  `json:"scope"`
	GoVersion           string  `json:"go_version"`
	UnicodeVersion      string  `json:"unicode_version"`
}

func fixture(root, op string, mib int) (int, int64, string, error) {
	f, e := os.OpenFile(root+"/input.csv", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return 0, 0, "", e
	}
	defer f.Close()
	expected := sha256.New()
	oracle := csv.NewWriter(expected)
	header := []string{"id", "target", "payload"}
	if e = oracle.Write(header); e != nil {
		return 0, 0, "", e
	}
	var buf bytes.Buffer
	encoder := csv.NewWriter(&buf)
	encode := func(row []string) []byte { buf.Reset(); _ = encoder.Write(row); encoder.Flush(); return buf.Bytes() }
	raw := encode(header)
	if _, e = f.Write(raw); e != nil {
		return 0, 0, "", e
	}
	size := int64(len(raw))
	count := 0
	rng := rand.New(rand.NewSource(20261022))
	noise := make([]byte, 512)
	for {
		sample := samples[count%len(samples)]
		payload := strings.Repeat("repeat,", 128)
		if count%2 == 1 {
			_, _ = rng.Read(noise)
			payload = hex.EncodeToString(noise)
		}
		row := []string{strconv.Itoa(count), sample.raw, payload}
		raw = encode(row)
		if size+int64(len(raw)) > int64(mib)<<20 {
			break
		}
		if _, e = f.Write(raw); e != nil {
			return 0, 0, "", e
		}
		size += int64(len(raw))
		// Independent planted oracle: explicit golden mappings, never calls transform.
		switch op {
		case "trim":
			row[1] = sample.trim
		case "lower":
			row[1] = sample.lower
		case "upper":
			row[1] = sample.upper
		case "replace":
			row[1] = sample.replace
		}
		if e = oracle.Write(row); e != nil {
			return 0, 0, "", e
		}
		count++
	}
	oracle.Flush()
	if e = oracle.Error(); e != nil {
		return 0, 0, "", e
	}
	if e = f.Sync(); e != nil {
		return 0, 0, "", e
	}
	return count, size, hex.EncodeToString(expected.Sum(nil)), nil
}

type enospcFailure struct{}

func (enospcFailure) Error() string { return "controlled_enospc" }

type encodedLimit struct {
	enospc     bool
	file       *os.File
	bytes, cap int64
}

func (w *encodedLimit) Write(p []byte) (int, error) {
	if int64(len(p)) > w.cap-w.bytes {
		return 0, fmt.Errorf("encoded_limit")
	}
	n, e := w.file.Write(p)
	if isENOSPC(e) {
		w.enospc = true
	}
	w.bytes += int64(n)
	return n, e
}

func trial(root, op string, mib int, scenario string) (metrics, error) {
	started := time.Now()
	rows, size, expected, e := fixture(root, op, mib)
	if e != nil {
		return metrics{}, e
	}
	fixtureTime := time.Since(started).Seconds()
	if scenario == "fs-full" {
		if e = fillPrivateFS(root); e != nil {
			return metrics{}, e
		}
	}
	raw, _ := json.Marshal(map[string]string{"column": "target", "op": op})
	if op == "replace" {
		raw, _ = json.Marshal(map[string]string{"column": "target", "op": op, "old": "aa", "new": "$1\\"})
	}
	if scenario == "late-expansion" {
		raw, _ = json.Marshal(map[string]string{"column": "target", "op": "replace", "old": "x", "new": strings.Repeat("y", 1024)})
		appendFile, err := os.OpenFile(root+"/input.csv", os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return metrics{}, err
		}
		csvOut := csv.NewWriter(appendFile)
		_ = csvOut.Write([]string{"late", strings.Repeat("x", 17), "tail"})
		csvOut.Flush()
		err = appendFile.Close()
		if err != nil {
			return metrics{}, err
		}
	}
	in, e := os.Open(root + "/input.csv")
	if e != nil {
		return metrics{}, e
	}
	defer in.Close()
	out, e := os.OpenFile(root+"/result.partial", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return metrics{}, e
	}
	sink := &encodedLimit{file: out, cap: 2 << 30}
	if scenario == "write-failure" {
		sink.cap = 256
	}
	zipper, e := gzip.NewWriterLevel(sink, gzip.BestSpeed)
	if e != nil {
		out.Close()
		return metrics{}, e
	}
	logical := sha256.New()
	started = time.Now()
	caps := tabular.StreamLimits{InputBytes: 1 << 30, OutputBytes: 2 << 30, Rows: 10_000_000}
	if scenario == "output-limit" {
		caps.OutputBytes = 64 << 10
	}
	stats, e := tabular.StreamTransform(in, io.MultiWriter(zipper, logical), raw, caps)
	if e != nil {
		zipper.Close()
		out.Close()
		if sink.enospc {
			return metrics{}, enospcFailure{}
		}
		return metrics{}, e
	}
	if e = zipper.Close(); e != nil {
		out.Close()
		if sink.enospc {
			return metrics{}, enospcFailure{}
		}
		return metrics{}, e
	}
	if e = out.Sync(); e != nil {
		out.Close()
		return metrics{}, e
	}
	if e = out.Close(); e != nil {
		return metrics{}, e
	}
	workerTime := time.Since(started).Seconds()
	started = time.Now()
	artifact, e := os.Open(root + "/result.partial")
	if e != nil {
		return metrics{}, e
	}
	defer artifact.Close()
	encodedHash := sha256.New()
	if _, e = io.Copy(encodedHash, artifact); e != nil {
		return metrics{}, e
	}
	if _, e = artifact.Seek(0, 0); e != nil {
		return metrics{}, e
	}
	unzip, e := gzip.NewReader(artifact)
	if e != nil {
		return metrics{}, e
	}
	verified := sha256.New()
	n, e := io.Copy(verified, io.LimitReader(unzip, (2<<30)+1))
	closeError := unzip.Close()
	actual := hex.EncodeToString(logical.Sum(nil))
	if e != nil || closeError != nil || n != stats.OutputBytes || actual != expected || hex.EncodeToString(verified.Sum(nil)) != expected || stats.Rows != rows || stats.InputBytes != size {
		return metrics{}, fmt.Errorf("oracle_mismatch")
	}
	if e = artifact.Close(); e != nil {
		return metrics{}, e
	}
	if e = os.Rename(root+"/result.partial", root+"/result.csv.gz"); e != nil {
		return metrics{}, e
	}
	return metrics{ProcessPeakRSSBytes: peakRSS(), Status: "ok", Operation: op, MiB: mib, Rows: rows, InputBytes: size, LogicalBytes: n, EncodedBytes: sink.bytes, LogicalHash: expected, EncodedHash: hex.EncodeToString(encodedHash.Sum(nil)), FixtureSeconds: fixtureTime, WorkerSeconds: workerTime, VerifySeconds: time.Since(started).Seconds(), Scope: "synthetic_only_provider_cleanup_and_billing_separate", GoVersion: runtime.Version(), UnicodeVersion: tabular.TransformUnicodeVersion}, nil
}

func main() {
	mib := flag.Int("mib", 16, "synthetic MiB")
	op := flag.String("op", "trim", "fixed transform")
	root := flag.String("work", "/work", "empty private scratch")
	probe := flag.String("probe", "", "fixed isolation probe")
	scenario := flag.String("scenario", "baseline", "fixed failure scenario")
	flag.Parse()
	fail := func() { fmt.Println(`{"status":"failed","code":"transform_trial_failed"}`); os.Exit(1) }
	if e := transformguard.Install(); e != nil {
		fail()
	}
	time.AfterFunc(840*time.Second, func() { os.Exit(124) })
	if *probe != "" {
		if !runProbe(*probe) {
			fail()
		}
		return
	}
	if *mib != 1 && *mib != 16 && *mib != 128 && *mib != 1024 {
		fail()
	}
	if *op != "trim" && *op != "lower" && *op != "upper" && *op != "replace" {
		fail()
	}
	if *scenario == "fs-full" {
		private, e := os.MkdirTemp("/dev/shm", "transform-enospc-")
		if e != nil {
			fail()
		}
		*root = private
	}
	stat, e := os.Lstat(*root)
	if e != nil || !stat.IsDir() || stat.Mode()&os.ModeSymlink != 0 || stat.Mode().Perm()&0077 != 0 || os.Getuid() == 0 {
		fail()
	}
	entries, e := os.ReadDir(*root)
	if e != nil || len(entries) != 0 {
		fail()
	}
	if *scenario != "baseline" && *scenario != "late-expansion" && *scenario != "output-limit" && *scenario != "write-failure" && *scenario != "fs-full" {
		fail()
	}
	m, e := trial(*root, *op, *mib, *scenario)
	if e != nil {
		if *scenario == "fs-full" && (errors.As(e, new(enospcFailure)) || isENOSPC(e)) {
			_, published := os.Stat(*root + "/result.csv.gz")
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "failed", "code": "output_unavailable", "enospc_observed": true, "published_absent": os.IsNotExist(published)})
			os.Exit(1)
		}
		code := "transform_trial_failed"
		var fixed *tabular.Error
		if errors.As(e, &fixed) {
			for _, allowed := range []string{"cell_limit", "output_byte_limit", "output_unavailable", "file_limit", "row_limit", "invalid_csv"} {
				if fixed.Code == allowed {
					code = allowed
				}
			}
		}
		if e.Error() == "encoded_limit" {
			code = "encoded_limit"
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"status": "failed", "code": code})
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(m)
}
