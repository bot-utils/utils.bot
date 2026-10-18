package parser

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestWorkerBuildHardeningAndNotices(t *testing.T) {
	_ = nativeFixture(t, "hello.pdf")
	for _, name := range []string{"pdfium-worker", "poppler-worker"} {
		file, err := elf.Open("/app/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if file.Type != elf.ET_DYN {
			t.Fatal("worker is not PIE", name)
		}
		relro := false
		for _, p := range file.Progs {
			if p.Type == elf.PT_GNU_STACK && p.Flags&elf.PF_X != 0 {
				t.Fatal("executable stack", name)
			}
			if p.Type == elf.PT_GNU_RELRO {
				relro = true
			}
		}
		flags, _ := file.DynValue(elf.DT_FLAGS)
		flags1, _ := file.DynValue(elf.DT_FLAGS_1)
		now := false
		for _, f := range flags {
			if f&uint64(elf.DF_BIND_NOW) != 0 {
				now = true
			}
		}
		for _, f := range flags1 {
			if f&uint64(elf.DF_1_NOW) != 0 {
				now = true
			}
		}
		if !relro || !now {
			t.Fatal("missing full RELRO", name)
		}
		symbols, err := file.DynamicSymbols()
		if err != nil {
			t.Fatal(err)
		}
		protector := false
		for _, symbol := range symbols {
			if symbol.Name == "__stack_chk_fail" {
				protector = true
			}
		}
		if !protector {
			t.Fatal("missing stack protector", name)
		}
		_ = file.Close()
	}
	for _, p := range []string{"/opt/pdfium/LICENSE", "/opt/pdfium/licenses/pdfium.txt", "/opt/pdfium/licenses/libopenjpeg.txt", "/opt/poppler/COPYING", "/opt/poppler/COPYING3"} {
		data, err := os.ReadFile(p)
		if err != nil || len(data) == 0 {
			t.Fatal("missing third party notice", p, err)
		}
	}
	args, err := os.ReadFile("/opt/pdfium/args.gn")
	if err != nil || !strings.Contains(string(args), "pdf_enable_v8 = false") || !strings.Contains(string(args), "pdf_enable_xfa = false") {
		t.Fatal("unexpected PDFium scripting configuration")
	}
	// Ask the retained dynamic loader to resolve the actual production binary.
	libs, err := exec.Command("/lib/ld-musl-aarch64.so.1", "--list", "/app/poppler-worker").CombinedOutput()
	if err != nil || strings.Contains(string(libs), "not found") {
		t.Fatal("missing runtime dependency", string(libs), err)
	}
	for _, unneeded := range []string{"libnss", "libsmime", "libsqlite", "libcurl", "libtiff", "libatomic", "libopenjp2", "libpng", "libbz2", "libjpeg", "libbrotli", "libc.so.6", "libstdc++", "libgcc_s"} {
		if strings.Contains(string(libs), unneeded) {
			t.Fatal("unneeded native dependency", unneeded)
		}
	}
	pdfium, err := os.ReadFile("/app/pdfium-worker")
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range [][]byte{[]byte("opj_setup_decoder"), []byte("opj_j2k_read_tlm"), []byte("OpenJpeg only supports"), []byte("CJBig2_Image"), []byte("JBig2_GRDProc")} {
		if bytes.Contains(pdfium, marker) {
			t.Fatal("disabled bundled raster decoder remains in runtime worker", string(marker))
		}
	}
	poppler, err := os.ReadFile("/opt/poppler/lib/libpoppler.so.165")
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range [][]byte{[]byte("JBIG2Stream"), []byte("readGenericBitmap"), []byte("readTextRegion")} {
		if bytes.Contains(poppler, marker) {
			t.Fatal("JBIG2 decoder remains in Poppler runtime library", string(marker))
		}
	}

}

func TestSandboxRefusesAllIoctlOperations(t *testing.T) {
	data := nativeFixture(t, "hello.pdf")
	cmd := exec.Command("/app/worker-test")
	cmd.Env = []string{"WORKER_TEST=ioctl"}
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.CombinedOutput()
	if err != nil || string(out) != "ioctl_denied" {
		t.Fatalf("ioctl refusal: %q, %v", out, err)
	}
}

func TestSandboxDeniesFilesAndExecutableMappings(t *testing.T) {
	data := nativeFixture(t, "hello.pdf")
	for _, mode := range []string{"open", "map_exec", "protect_exec"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command("/app/worker-test")
			cmd.Env = []string{"WORKER_TEST=" + mode}
			cmd.Stdin = strings.NewReader(string(data))
			err := cmd.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatal("expected confined worker termination", err)
			}
			status := exit.Sys().(syscall.WaitStatus)
			if !status.Signaled() || status.Signal() != syscall.SIGSYS {
				t.Fatal("operation was not denied", status)
			}
		})
	}
}

func TestWarmupDescriptorsAndTextCountsAreBounded(t *testing.T) {
	data := nativeFixture(t, "hello.pdf")
	for _, tc := range []struct{ mode, want string }{{"warm_descriptor", "warm_descriptor_closed"}, {"text_bounds", "text_count_bounded"}} {
		t.Run(tc.mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/app/worker-test")
			cmd.Env = []string{"WORKER_TEST=" + tc.mode}
			cmd.Stdin = bytes.NewReader(data)
			out, err := cmd.CombinedOutput()
			if err != nil || string(out) != tc.want {
				t.Fatalf("worker boundary check: %v %s", err, out)
			}
		})
	}
}

func nativeFixture(t *testing.T, name string) []byte {
	t.Helper()
	if os.Getenv("PDF_NATIVE_TEST") != "1" {
		t.Skip("run scripts/test-native.sh for real confined engines")
	}
	data, err := os.ReadFile(filepath.Join("/testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func TestNativeEngines(t *testing.T) {
	data := nativeFixture(t, "hello.pdf")
	p := Parser{Dir: "/app"}
	for _, engine := range []string{"pdfium", "poppler"} {
		t.Run(engine, func(t *testing.T) {
			r, _, err := p.attempt(context.Background(), engine, data)
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Pages) != 1 || !strings.Contains(r.Pages[0].Text, "Hello from the paid PDF prototype.") {
				t.Fatalf("unexpected extraction %+v", r)
			}
		})
	}
}

func TestBothNativeEnginesMarkPageLimitedResultsPartial(t *testing.T) {
	_ = nativeFixture(t, "hello.pdf")
	// Ordinary 101-page PDF with exact xref offsets; generated using only Go's
	// standard library. This exercises real engine truncation, not a fake result.
	objects := []string{"<< /Type /Catalog /Pages 2 0 R >>", "", "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"}
	kids := make([]string, 101)
	for i := range kids {
		page := len(objects) + 1
		kids[i] = fmt.Sprintf("%d 0 R", page)
		text := fmt.Sprintf("BT /F1 12 Tf 72 720 Td (Ordinary page %d) Tj ET", i+1)
		objects = append(objects, fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>", page+1), fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(text), text))
	}
	objects[1] = fmt.Sprintf("<< /Type /Pages /Count 101 /Kids [%s] >>", strings.Join(kids, " "))
	var pdf bytes.Buffer
	pdf.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects))
	for i, object := range objects {
		offsets[i] = pdf.Len()
		fmt.Fprintf(&pdf, "%d 0 obj\n%s\nendobj\n", i+1, object)
	}
	xref := pdf.Len()
	fmt.Fprintf(&pdf, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, offset := range offsets {
		fmt.Fprintf(&pdf, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&pdf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	p := Parser{Dir: "/app"}
	for _, engine := range []string{"pdfium", "poppler"} {
		t.Run(engine, func(t *testing.T) {
			r, _, err := p.attempt(context.Background(), engine, pdf.Bytes())
			if err != nil || r.PageCount != 101 || len(r.Pages) != 100 || !r.Truncated || !strings.Contains(r.Pages[99].Text, "Ordinary page 100") {
				t.Fatalf("incorrect native page truncation: engine=%s pages=%d total=%d partial=%v error=%v", engine, len(r.Pages), r.PageCount, r.Truncated, err)
			}
		})
	}
}
func TestHealthyAlongsideInvalidDocument(t *testing.T) {
	good, bad := nativeFixture(t, "hello.pdf"), nativeFixture(t, "bad.pdf")
	p := Parser{Dir: "/app"}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		r, err := p.Parse(context.Background(), good)
		if err != nil || len(r.Pages) != 1 {
			t.Errorf("healthy failed: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		r, err := p.Parse(context.Background(), bad)
		if !errors.Is(err, ErrDocument) || len(r.Attempts) != 2 || r.Attempts[0].Engine != "pdfium" || r.Attempts[1].Engine != "poppler" {
			t.Errorf("bad waterfall: attempts=%+v error=%v", r.Attempts, err)
		}
	}()
	wg.Wait()
}

func TestParsingCascadeToRealPoppler(t *testing.T) {
	data := nativeFixture(t, "hello.pdf")
	for _, tc := range []struct{ mode, outcome string }{
		{"document-error", "document_error"}, {"empty", "success"},
		{"invalid-output", "invalid_output"}, {"timeout", "timeout"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			p := Parser{Dir: "/cascade/" + tc.mode, Timeout: time.Second}
			r, err := p.Parse(context.Background(), data)
			if err != nil || r.SelectedEngine != "poppler" || len(r.Pages) != 1 || !strings.Contains(r.Pages[0].Text, "Hello from the paid PDF prototype.") {
				t.Fatalf("real Poppler fallback failed: result=%+v error=%v", r, err)
			}
			want := []Attempt{{Engine: "pdfium", Outcome: tc.outcome}, {Engine: "poppler", Outcome: "success"}}
			if len(r.Attempts) != len(want) || r.Attempts[0] != want[0] || r.Attempts[1] != want[1] {
				t.Fatalf("incorrect cascade history: %+v", r.Attempts)
			}
		})
	}
}

func TestParsingCascadeStopsForSetupAndPassword(t *testing.T) {
	data := nativeFixture(t, "hello.pdf")
	for _, tc := range []struct {
		mode, outcome string
		err           error
	}{{"setup-failed", "setup_failed", ErrSetup}, {"password-required", "password_required", ErrDocument}} {
		t.Run(tc.mode, func(t *testing.T) {
			r, err := (Parser{Dir: "/cascade/" + tc.mode}).Parse(context.Background(), data)
			if !errors.Is(err, tc.err) || len(r.Attempts) != 1 || r.Attempts[0] != (Attempt{Engine: "pdfium", Outcome: tc.outcome}) {
				t.Fatalf("unexpected fallback: %+v %v", r, err)
			}
		})
	}
}

func TestParsingCascadeStopsAfterPrimarySuccess(t *testing.T) {
	data := nativeFixture(t, "hello.pdf")
	r, err := (Parser{Dir: "/app"}).Parse(context.Background(), data)
	if err != nil || r.SelectedEngine != "pdfium" || len(r.Attempts) != 1 || r.Attempts[0] != (Attempt{Engine: "pdfium", Outcome: "success"}) {
		t.Fatalf("unexpected fallback after real PDFium success: %+v %v", r, err)
	}
}

func TestBlankDocumentCascadesThroughBothRealEngines(t *testing.T) {
	data := nativeFixture(t, "hello.pdf")
	text := []byte("Hello from the paid PDF prototype.")
	if !bytes.Contains(data, text) {
		t.Fatal("expected ordinary uncompressed text fixture")
	}
	blank := bytes.Replace(data, text, bytes.Repeat([]byte{' '}, len(text)), 1)
	r, err := (Parser{Dir: "/app"}).Parse(context.Background(), blank)
	if err != nil || len(r.Attempts) != 2 || r.Attempts[0].Engine != "pdfium" || r.Attempts[1].Engine != "poppler" || len(r.Warnings) != 1 || r.Warnings[0] != "no_extractable_text" {
		t.Fatalf("blank document waterfall: %+v %v", r, err)
	}
	for _, page := range r.Pages {
		if strings.TrimSpace(page.Text) != "" {
			t.Fatal("blank fixture produced text")
		}
	}
}
func TestSandboxCannotSignalSupervisor(t *testing.T) {
	data := nativeFixture(t, "hello.pdf")
	cmd := exec.Command("/app/worker-test")
	cmd.Env = []string{"WORKER_TEST=signal"}
	cmd.Stdin = strings.NewReader(string(data))
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("expected worker termination: %v", err)
	}
	status := exit.Sys().(syscall.WaitStatus)
	if !status.Signaled() || status.Signal() != syscall.SIGSYS {
		t.Fatalf("signal syscall was not contained: %v", status)
	}
}
func TestHungWorkerDoesNotBlockHealthy(t *testing.T) {
	data := nativeFixture(t, "hello.pdf")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/app/worker-test")
	cmd.Env = []string{"WORKER_TEST=spin"}
	cmd.Stdin = strings.NewReader(string(data))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	r, err := (Parser{Dir: "/app"}).Parse(context.Background(), data)
	if err != nil || len(r.Pages) != 1 {
		t.Fatal("healthy parse failed while sibling spun")
	}
	if err = cmd.Wait(); err == nil || ctx.Err() == nil {
		t.Fatal("hung worker not killed/reaped on deadline")
	}
}
func TestOutputFloodIsBoundedAndHealthySurvives(t *testing.T) {
	data := nativeFixture(t, "hello.pdf")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/app/worker-test")
	cmd.Env = []string{"WORKER_TEST=flood"}
	cmd.Stdin = strings.NewReader(string(data))
	output := &limitedBuffer{cap: 1024, cancel: cancel}
	cmd.Stdout = output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	r, err := (Parser{Dir: "/app"}).Parse(context.Background(), data)
	if err != nil || len(r.Pages) != 1 {
		t.Fatal("healthy parse failed while sibling flooded")
	}
	_ = cmd.Wait()
	if !output.exceeded || output.b.Len() > 1024 {
		t.Fatal("output not bounded")
	}
}

func TestMinimalRuntimeInventory(t *testing.T) {
	_ = nativeFixture(t, "hello.pdf")
	for _, path := range []string{"/bin/sh", "/bin/bash", "/usr/bin/apt", "/usr/bin/dpkg", "/usr/bin/python3", "/usr/bin/curl", "/usr/bin/ldd", "/var/lib/apt", "/opt/poppler/lib/pkgconfig"} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("unnecessary runtime path", path, err)
		}
	}
	var manifest struct {
		Components []struct{ Name, Version, Kind string }
		Files      map[string]string
	}
	data, err := os.ReadFile("/usr/share/agent-pdf/runtime.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Files) < 20 || len(manifest.Components) < 10 {
		t.Fatal("empty runtime inventory")
	}
	expat := false
	removed := map[string]bool{
		"libbz2-1.0": false, "libopenjp2-7": false, "libpng16-16t64": false,
		"libjpeg62-turbo": false, "libbrotli1": false,
	}
	for _, component := range manifest.Components {
		if _, unwanted := removed[component.Name]; unwanted {
			t.Fatal("unused image codec remains in runtime inventory", component.Name)
		}
		if component.Name == "libexpat1" {
			t.Fatal("stale Debian Expat inventory")
		}
		if component.Name == "expat" && component.Version == "2.9.0" {
			expat = true
		}
	}
	if !expat {
		t.Fatal("missing patched Expat version")
	}
	libcppFound := false
	forbiddenLibcImports := map[string]bool{
		"glob": true, "glob64": true, "regexec": true, "strfmon": true,
		"tdelete": true, "wordexp": true, "ns_sprintrr": true, "ns_name_unpack": true,
	}
	for path, want := range manifest.Files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("inventory file absent", path, err)
		}
		hash := sha256.Sum256(data)
		if hex.EncodeToString(hash[:]) != want {
			t.Fatal("inventory hash mismatch", path)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
			t.Fatal("privileged runtime file", path)
		}
		if strings.Contains(filepath.Base(path), "libstdc++") || strings.Contains(filepath.Base(path), "libgcc_s") || strings.HasSuffix(path, "/libc.so.6") {
			t.Fatal("GNU runtime dependency returned", path)
		}
		if strings.Contains(filepath.Base(path), "libc++.so.1") {
			libcppFound = true
		}
		if len(data) >= 4 && bytes.Equal(data[:4], []byte("\x7fELF")) {
			binary, err := elf.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			imports, err := binary.ImportedSymbols()
			_ = binary.Close()
			if err == nil {
				for _, symbol := range imports {
					if forbiddenLibcImports[symbol.Name] {
						t.Fatal("untrusted runtime gained an affected glibc API edge", path, symbol.Name)
					}
				}
			}
		}
	}
	if !libcppFound {
		t.Fatal("missing LLVM libc++ runtime inventory")
	}
	for _, worker := range []string{"/app/pdfium-worker", "/app/poppler-worker"} {
		data, err := os.ReadFile(worker)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("__gnu_pbds")) || bytes.Contains(data, []byte("binary_heap_tag")) {
			t.Fatal("CVE-2026-102010 policy-based heap code present", worker)
		}
	}
	// Expat may only parse immutable font configuration during trusted warmup;
	// neither the parser wrapper nor PDF parser has an XML entrypoint.
	libs, err := exec.Command("/lib/ld-musl-aarch64.so.1", "--list", "/app/poppler-worker").CombinedOutput()
	if err != nil || !strings.Contains(string(libs), "libexpat.so.1") {
		t.Fatal("patched Expat not linked", string(libs), err)
	}
	for _, p := range []string{"/etc/ssl/certs/ca-certificates.crt", "/opt/expat/COPYING", "/usr/share/licenses/musl-COPYRIGHT", "/usr/share/licenses/libcxx-LICENSE.TXT", "/usr/share/licenses/libcxxabi-LICENSE.TXT", "/usr/share/licenses/libunwind-LICENSE.TXT", "/usr/share/licenses/compiler-rt-LICENSE.TXT", "/lib/apk/db/installed"} {
		data, err := os.ReadFile(p)
		if err != nil || len(data) == 0 {
			t.Fatal("missing runtime asset", p, err)
		}
	}
	for _, p := range []string{"/usr/lib/aarch64-linux-gnu/gconv/SHIFT_JISX0213.so", "/usr/lib/aarch64-linux-gnu/gconv/EUC-JISX0213.so", "/usr/sbin/nscd", "/usr/bin/ldd"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatal("affected glibc module/tool present", p, err)
		}
	}
}

func TestPatchedExpatAndUnicodeCodecs(t *testing.T) {
	_ = nativeFixture(t, "hello.pdf")
	output, err := exec.Command("/app/runtime-check").CombinedOutput()
	if err != nil || !strings.Contains(string(output), "expat_2.9.0") {
		t.Fatal("runtime compatibility", string(output), err)
	}
}

func TestSourceBuiltPDFiumProvenance(t *testing.T) {
	_ = nativeFixture(t, "hello.pdf")
	var provenance struct {
		SourceCommit, ArgsSHA256, BundledFreetypePatch, BundledZlibPatch, Compiler string
		RasterDisablePatchSHA256, MuslBuildPatchSHA256                             string
		DisabledRasterDecoders                                                     []string
		SourceHashes, BuildSourceHashes                                            map[string]string
	}
	data, err := os.ReadFile("/opt/pdfium/provenance.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &provenance); err != nil {
		t.Fatal(err)
	}
	if provenance.SourceCommit != "2fd6cff57d9412cc42ef1a7e4e0a59b13a1e7cec" || provenance.Compiler == "" || len(provenance.SourceHashes) != 3 || provenance.BundledFreetypePatch != "f3ca71c9900fe860849b3163a6e2c1e765b291d9" || provenance.BundledZlibPatch != "df84af25dc1942490e1d1c899a07619152a46148" || !slices.Equal(provenance.DisabledRasterDecoders, []string{"JBIG2Decode", "JPXDecode"}) || provenance.RasterDisablePatchSHA256 != "c3ffebb7e0f0674b40acf416c4ec3e3c0d390da7a93478bf13f4a6ac0fe2af1c" {
		t.Fatal("unexpected parser provenance", provenance)
	}
	if provenance.MuslBuildPatchSHA256 != "0907bee72c60439639ca454cf5bd86e14be21e953511a7c1fb77e8eda4765bfc" || len(provenance.BuildSourceHashes) != 2 {
		t.Fatal("missing musl build provenance", provenance)
	}
	patch, err := os.ReadFile("/usr/share/agent-pdf/patches/pdfium-musl-build.patch")
	if err != nil {
		t.Fatal(err)
	}
	patchHash := sha256.Sum256(patch)
	if hex.EncodeToString(patchHash[:]) != provenance.MuslBuildPatchSHA256 {
		t.Fatal("musl build patch differs from provenance")
	}
	args, err := os.ReadFile("/opt/pdfium/args.gn")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(args)
	if hex.EncodeToString(hash[:]) != provenance.ArgsSHA256 {
		t.Fatal("parser build configuration differs from provenance")
	}
	if _, err := os.Stat("/opt/pdfium/lib/libpdfium.so"); !os.IsNotExist(err) {
		t.Fatal("old prebuilt parser remains")
	}
}

func rasterFilterFixture(filter string, includeText bool) []byte {
	content := "q 1 0 0 1 0 0 cm /Im Do Q\n"
	if includeText {
		content += "BT /F1 12 Tf 72 720 Td (A) Tj ET\nBT /F2 12 Tf 72 690 Td (TYPE3 JPX JBIG2 SENTINEL) Tj ET\n"
	}
	charProc := "600 0 d0 q 1 0 0 1 0 0 cm /Im Do Q"
	cmap := "/CIDInit /ProcSet findresource begin 12 dict begin begincmap /CMapType 2 def 1 begincodespacerange <00> <FF> endcodespacerange 1 beginbfchar <41> <0041> endbfchar endcmap CMapName currentdict /CMap defineresource pop end end"
	image := "not-a-raster-code-stream"
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R /F2 9 0 R >> /XObject << /Im 7 0 R >> >> /Contents 4 0 R >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content),
		"<< /Type /Font /Subtype /Type3 /Name /F1 /FontBBox [0 0 1000 1000] /FontMatrix [.001 0 0 .001 0 0] /CharProcs << /A 6 0 R >> /Encoding << /Type /Encoding /Differences [65 /A] >> /FirstChar 65 /LastChar 65 /Widths [600] /Resources << /XObject << /Im 7 0 R >> >> /ToUnicode 8 0 R >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(charProc), charProc),
		fmt.Sprintf("<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /%s /Length %d >>\nstream\n%s\nendstream", filter, len(image), image),
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(cmap), cmap),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}
	var pdf bytes.Buffer
	pdf.WriteString("%PDF-1.7\n")
	offsets := make([]int, len(objects))
	for i, object := range objects {
		offsets[i] = pdf.Len()
		fmt.Fprintf(&pdf, "%d 0 obj\n%s\nendobj\n", i+1, object)
	}
	xref := pdf.Len()
	fmt.Fprintf(&pdf, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, offset := range offsets {
		fmt.Fprintf(&pdf, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&pdf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return pdf.Bytes()
}

func TestDisabledRasterCodecsPreserveTextAndIsolation(t *testing.T) {
	good := nativeFixture(t, "hello.pdf")
	const text = "TYPE3 JPX JBIG2 SENTINEL"
	for _, filter := range []string{"JPXDecode", "JBIG2Decode"} {
		t.Run(filter, func(t *testing.T) {
			withText := rasterFilterFixture(filter, true)
			for _, engine := range []string{"pdfium", "poppler"} {
				r, _, err := (Parser{Dir: "/app"}).attempt(context.Background(), engine, withText)
				if err != nil || len(r.Pages) != 1 || !strings.Contains(r.Pages[0].Text, text) || !strings.Contains(r.Pages[0].Text, "A") {
					t.Fatalf("text changed around disabled raster codec: engine=%s result=%+v error=%v", engine, r, err)
				}
			}
			r, err := (Parser{Dir: "/cascade/document-error"}).Parse(context.Background(), withText)
			if err != nil || r.SelectedEngine != "poppler" || !strings.Contains(r.Pages[0].Text, text) {
				t.Fatalf("fallback changed around disabled raster codec: result=%+v error=%v", r, err)
			}
			blank, err := (Parser{Dir: "/app"}).Parse(context.Background(), rasterFilterFixture(filter, false))
			if err != nil || len(blank.Warnings) != 1 || blank.Warnings[0] != "no_extractable_text" {
				t.Fatalf("image-only result changed: result=%+v error=%v", blank, err)
			}
			clean, err := (Parser{Dir: "/app"}).Parse(context.Background(), good)
			if err != nil || len(clean.Pages) != 1 || !strings.Contains(clean.Pages[0].Text, "Hello from the paid PDF prototype.") || strings.Contains(clean.Pages[0].Text, text) {
				t.Fatalf("clean sentinel failed after raster control: result=%+v error=%v", clean, err)
			}
		})
	}
}

// Deterministic malformed controls exercise crash/cascade isolation without
// importing weaponized samples. Every case is followed by a clean parse in new
// worker processes, which also checks that text from the prior process cannot
// bleed into the next response.
func TestDeterministicMalformedCorpusIsolation(t *testing.T) {
	good := nativeFixture(t, "hello.pdf")
	const sentinel = "Hello from the paid PDF prototype."
	if !bytes.Contains(good, []byte(sentinel)) {
		t.Fatal("sentinel fixture changed")
	}

	type mutation struct {
		name string
		data []byte
	}
	mutations := make([]mutation, 0, 48)
	marked := func(index int) []byte {
		marker := fmt.Sprintf("MUTATION_CASE_%02d_ISOLATED_PAYLOAD.", index)
		if len(marker) != len(sentinel) {
			t.Fatal("mutation marker length changed")
		}
		return bytes.Replace(good, []byte(sentinel), []byte(marker), 1)
	}

	for _, length := range []int{1, 4, 8, 16, 32, 64, len(good) / 4, len(good) / 2, len(good) - 8, len(good) - 1} {
		data := marked(len(mutations))
		mutations = append(mutations, mutation{fmt.Sprintf("truncate-%d", length), append([]byte(nil), data[:length]...)})
	}
	replacements := [][2]string{
		{"%PDF-1.4", "%PDF-9.9"}, {"xref", "xraf"}, {"trailer", "trailxr"}, {"startxref", "startxraf"},
		{"%%EOF", "%%EOX"}, {"/Catalog", "/Catxlog"}, {"/Pages", "/Pagxs"}, {"/Page ", "/Pagx "},
		{"/Count 1", "/Count X"}, {"/Kids", "/Kidx"}, {"/MediaBox", "/MediaB0x"}, {"/Resources", "/Resourcxs"},
		{"/Font", "/F0nt"}, {"/Type1", "/Typx1"}, {"/Helvetica", "/Helveticx"}, {"/Contents", "/Contxnts"},
		{"/Length 65", "/Length XX"}, {"stream", "strxam"}, {"endstream", "endstrxam"}, {"endobj", "endobx"},
	}
	for _, replacement := range replacements {
		data := marked(len(mutations))
		if !bytes.Contains(data, []byte(replacement[0])) {
			t.Fatalf("fixture lacks token %q", replacement[0])
		}
		data = bytes.Replace(data, []byte(replacement[0]), []byte(replacement[1]), 1)
		mutations = append(mutations, mutation{"replace-" + replacement[0], data})
	}
	for i := 0; len(mutations) < 48; i++ {
		data := marked(len(mutations))
		// An LCG-derived position makes this corpus stable while spreading flips
		// across headers, objects, streams and xref data.
		position := int((uint64(i+1)*1103515245 + 12345) % uint64(len(data)))
		data[position] ^= byte(0x21 + i%31)
		mutations = append(mutations, mutation{fmt.Sprintf("flip-%03d", position), data})
	}
	if len(mutations) != 48 {
		t.Fatalf("mutation corpus size=%d", len(mutations))
	}

	p := Parser{Dir: "/app", Timeout: 500 * time.Millisecond}
	outcomes := map[string]int{}
	for i, mutation := range mutations {
		result, err := p.Parse(context.Background(), mutation.data)
		if errors.Is(err, ErrSetup) || err != nil && !errors.Is(err, ErrDocument) {
			t.Fatalf("case %d %s escaped document isolation: result=%+v error=%v", i, mutation.name, result, err)
		}
		for _, attempt := range result.Attempts {
			outcomes[attempt.Outcome]++
		}
		if err == nil {
			for _, page := range result.Pages {
				if strings.Contains(page.Text, sentinel) {
					t.Fatalf("case %d %s returned trusted warmup/sentinel text", i, mutation.name)
				}
			}
		}

		clean, cleanErr := p.Parse(context.Background(), good)
		if cleanErr != nil || clean.PageCount != 1 || len(clean.Pages) != 1 || !strings.Contains(clean.Pages[0].Text, sentinel) || strings.Contains(clean.Pages[0].Text, "MUTATION_CASE_") {
			t.Fatalf("case %d %s damaged or contaminated following parse: result=%+v error=%v", i, mutation.name, clean, cleanErr)
		}
	}
	t.Logf("48 malformed controls remained isolated; attempt outcomes=%v", outcomes)
}
