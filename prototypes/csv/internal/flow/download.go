package flow

import (
	"strconv"
	"strings"
)

type Download struct {
	Data       []byte
	Manifest   Manifest
	Start, End int
	Lease      string
	Partial    bool
}

// parseRange accepts one bounded encoded-byte range, including suffix/open end.
func parseRange(header string, size int) (int, int, error) {
	if header == "" {
		return 0, size - 1, nil
	}
	if !strings.HasPrefix(header, "bytes=") || strings.Contains(header, ",") {
		return 0, 0, fail(416, "invalid_range")
	}
	p := strings.Split(strings.TrimPrefix(header, "bytes="), "-")
	if len(p) != 2 {
		return 0, 0, fail(416, "invalid_range")
	}
	if p[0] == "" {
		n, err := strconv.Atoi(p[1])
		if err != nil || n <= 0 {
			return 0, 0, fail(416, "invalid_range")
		}
		return max(0, size-n), size - 1, nil
	}
	a, err := strconv.Atoi(p[0])
	if err != nil || a < 0 || a >= size {
		return 0, 0, fail(416, "invalid_range")
	}
	b := size - 1
	if p[1] != "" {
		b, err = strconv.Atoi(p[1])
		if err != nil || b < a {
			return 0, 0, fail(416, "invalid_range")
		}
		b = min(b, size-1)
	}
	return a, b, nil
}
func (e *Engine) InspectResult(id, cap string) (Manifest, error) {
	var out Manifest
	err := e.Store.tx(false, func(d *database) error {
		j, err := auth(d, id, cap)
		if err != nil {
			return err
		}
		if j.Financial != "PAID" {
			return fail(402, "result_unpaid")
		}
		if j.Artifact != "RETRIEVABLE" || e.now() >= j.ResultUntil || j.Cancel {
			return fail(410, "result_expired")
		}
		if err := verify(j.Result, j.Manifest); err != nil {
			return err
		}
		out = *j.Manifest
		return nil
	})
	return out, err
}
func (e *Engine) BeginDownload(id, cap, attempt, rangeHeader string) (Download, error) {
	var out Download
	if !secret(attempt) {
		return out, fail(400, "download_attempt_required")
	}
	err := e.Store.tx(true, func(d *database) error {
		j, err := auth(d, id, cap)
		if err != nil {
			return err
		}
		if j.Financial != "PAID" {
			return fail(402, "result_unpaid")
		}
		if j.Artifact != "RETRIEVABLE" || e.now() >= j.ResultUntil || j.Cancel {
			return fail(410, "result_expired")
		}
		if err := verify(j.Result, j.Manifest); err != nil {
			return err
		}
		start, end, err := parseRange(rangeHeader, len(j.Result))
		if err != nil {
			return err
		}
		if _, used := j.Downloads[attempt]; used {
			return fail(409, "attempt_replayed")
		}
		if len(j.Downloads) >= 128 {
			return fail(429, "download_attempt_limit")
		}
		if j.ActiveDownload != "" && j.Downloads[j.ActiveDownload].Until > e.now() {
			return fail(409, "download_active")
		}
		active := 0
		for _, v := range d.Jobs {
			if v.ActiveDownload != "" && v.Downloads[v.ActiveDownload].Until > e.now() {
				active++
			}
		}
		if active >= 2 {
			return fail(429, "download_capacity")
		}
		n := end - start + 1
		if n > 3*j.Manifest.EncodedBytes-j.DownloadUsed {
			return fail(429, "download_budget_exhausted")
		}
		lease := random()
		j.DownloadUsed += n
		j.Downloads[attempt] = download{Bytes: n, Lease: lease, Until: e.now() + 90}
		j.ActiveDownload = attempt
		out = Download{Data: j.Result[start : end+1], Manifest: *j.Manifest, Start: start, End: end, Lease: lease, Partial: rangeHeader != ""}
		return nil
	})
	return out, err
}
func (e *Engine) DownloadAllowed(id, lease string) bool {
	ok := false
	_ = e.Store.tx(false, func(d *database) error {
		j := d.Jobs[id]
		if j != nil && j.ActiveDownload != "" {
			v := j.Downloads[j.ActiveDownload]
			ok = v.Lease == lease && v.Until > e.now() && j.Artifact == "RETRIEVABLE" && !j.Cancel && e.now() < j.ResultUntil
		}
		return nil
	})
	return ok
}
func (e *Engine) EndDownload(id, lease string) error {
	return e.Store.tx(true, func(d *database) error {
		j := d.Jobs[id]
		if j == nil || j.ActiveDownload == "" {
			return nil
		}
		if j.Downloads[j.ActiveDownload].Lease != lease {
			return fail(409, "stale_download")
		}
		j.ActiveDownload = ""
		if j.Artifact == "DELETING" && j.Token == "" {
			j.erase()
		}
		return nil
	})
}
