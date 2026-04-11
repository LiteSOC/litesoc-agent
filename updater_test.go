package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// errReader always returns an error on Read.
type errReader struct{}

func (e *errReader) Read([]byte) (int, error) { return 0, fmt.Errorf("mock read error") }

// errBodyTransport wraps a RoundTripper and replaces the response body with
// an errReader so io.ReadAll always fails.
type errBodyTransport struct {
	inner http.RoundTripper
}

func (t *errBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.inner.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(&errReader{})
	return resp, nil
}

// ============================================
// Test Helpers
// ============================================

// createTestTarGz builds a tar.gz archive in a temp dir and returns its path.
func createTestTarGz(t *testing.T, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "archive.tar.gz")
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name:     name,
			Size:     int64(len(content)),
			Mode:     0755,
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatalf("write tar body: %v", err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close file: %v", err)
	}
	return archivePath
}

// sha256File computes the hex-encoded SHA-256 hash of a file.
func sha256File(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatalf("hash: %v", err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// stubUpdaterVars saves and restores all injectable updater vars.
func stubUpdaterVars(t *testing.T) {
	t.Helper()
	origInstall := installBinary
	origRestart := restartService
	origExec := osExecutable
	origSymlinks := evalSymlinks
	t.Cleanup(func() {
		installBinary = origInstall
		restartService = origRestart
		osExecutable = origExec
		evalSymlinks = origSymlinks
	})
}

// ============================================
// downloadFile
// ============================================

func TestDownloadFile_Success(t *testing.T) {
	content := []byte("hello binary content")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "out")
	if err := downloadFile(srv.Client(), srv.URL, dest); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("got %q; want %q", got, content)
	}
}

func TestDownloadFile_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "out")
	err := downloadFile(srv.Client(), srv.URL, dest)
	if err == nil {
		t.Fatal("expected error for HTTP 404")
	}
	if !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("error = %v; want HTTP 404", err)
	}
}

func TestDownloadFile_NetworkError(t *testing.T) {
	client := &http.Client{Timeout: time.Second}
	if err := downloadFile(client, "http://127.0.0.1:1/file", "/tmp/x"); err == nil {
		t.Fatal("expected error for unreachable server")
	}
}

func TestDownloadFile_InvalidDest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("data"))
	}))
	defer srv.Close()

	if err := downloadFile(srv.Client(), srv.URL, "/nonexistent/dir/file"); err == nil {
		t.Fatal("expected error for invalid dest path")
	}
}

// ============================================
// verifyChecksum
// ============================================

func TestVerifyChecksum_Match(t *testing.T) {
	archivePath := createTestTarGz(t, map[string][]byte{"litesoc-agent": []byte("binary")})
	hash := sha256File(t, archivePath)
	archiveName := fmt.Sprintf("litesoc-agent_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  %s\n", hash, archiveName)
	}))
	defer srv.Close()

	if err := verifyChecksum(srv.Client(), srv.URL, archivePath); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyChecksum_Mismatch(t *testing.T) {
	archivePath := createTestTarGz(t, map[string][]byte{"litesoc-agent": []byte("binary")})
	archiveName := fmt.Sprintf("litesoc-agent_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "0000000000000000000000000000000000000000000000000000000000000000  %s\n", archiveName)
	}))
	defer srv.Close()

	err := verifyChecksum(srv.Client(), srv.URL, archivePath)
	if err == nil {
		t.Fatal("expected hash mismatch error")
	}
	if !strings.Contains(err.Error(), "hash mismatch") {
		t.Errorf("error = %v; want 'hash mismatch'", err)
	}
}

func TestVerifyChecksum_HTTPNotAvailable(t *testing.T) {
	archivePath := createTestTarGz(t, map[string][]byte{"litesoc-agent": []byte("binary")})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	// Non-200 → skip verification, return nil.
	if err := verifyChecksum(srv.Client(), srv.URL, archivePath); err != nil {
		t.Fatalf("expected nil for non-200 checksum, got: %v", err)
	}
}

func TestVerifyChecksum_ArchiveNotListed(t *testing.T) {
	archivePath := createTestTarGz(t, map[string][]byte{"litesoc-agent": []byte("binary")})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "abc123  some_other_file.tar.gz")
	}))
	defer srv.Close()

	// Archive name not in checksum file → skip, return nil.
	if err := verifyChecksum(srv.Client(), srv.URL, archivePath); err != nil {
		t.Fatalf("expected nil when archive not listed, got: %v", err)
	}
}

func TestVerifyChecksum_DownloadError(t *testing.T) {
	client := &http.Client{Timeout: time.Second}
	err := verifyChecksum(client, "http://127.0.0.1:1/checksums", "/tmp/archive")
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
	if !strings.Contains(err.Error(), "download checksums") {
		t.Errorf("error = %v; want 'download checksums'", err)
	}
}

func TestVerifyChecksum_OpenArchiveError(t *testing.T) {
	archiveName := fmt.Sprintf("litesoc-agent_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a checksum line that contains the expected archive name so the
		// function proceeds to open the archive file.
		fmt.Fprintf(w, "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abcd  %s\n", archiveName)
	}))
	defer srv.Close()

	err := verifyChecksum(srv.Client(), srv.URL, "/nonexistent/archive.tar.gz")
	if err == nil {
		t.Fatal("expected error for missing archive file")
	}
}

// ============================================
// extractBinary
// ============================================

func TestExtractBinary_Success(t *testing.T) {
	content := []byte("#!/bin/sh\necho hello")
	archivePath := createTestTarGz(t, map[string][]byte{"litesoc-agent": content})
	destPath := filepath.Join(t.TempDir(), "litesoc-agent")

	if err := extractBinary(archivePath, destPath); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("content = %q; want %q", got, content)
	}
}

func TestExtractBinary_SubdirectoryPath(t *testing.T) {
	content := []byte("binary-v2")
	archivePath := createTestTarGz(t, map[string][]byte{"dist/litesoc-agent": content})
	destPath := filepath.Join(t.TempDir(), "litesoc-agent")

	if err := extractBinary(archivePath, destPath); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, _ := os.ReadFile(destPath)
	if string(got) != string(content) {
		t.Errorf("content = %q; want %q", got, content)
	}
}

func TestExtractBinary_NoBinaryInArchive(t *testing.T) {
	archivePath := createTestTarGz(t, map[string][]byte{"README.md": []byte("readme")})
	destPath := filepath.Join(t.TempDir(), "litesoc-agent")

	err := extractBinary(archivePath, destPath)
	if err == nil {
		t.Fatal("expected error for missing binary")
	}
	if !strings.Contains(err.Error(), "binary not found") {
		t.Errorf("error = %v; want 'binary not found'", err)
	}
}

func TestExtractBinary_InvalidGzip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.tar.gz")
	_ = os.WriteFile(path, []byte("not gzip data at all"), 0600)

	if err := extractBinary(path, filepath.Join(t.TempDir(), "out")); err == nil {
		t.Fatal("expected error for invalid gzip")
	}
}

func TestExtractBinary_CorruptTar(t *testing.T) {
	// Valid gzip wrapping invalid tar data → tr.Next() returns non-EOF error.
	dir := t.TempDir()
	path := filepath.Join(dir, "corrupt.tar.gz")
	f, _ := os.Create(path)
	gw := gzip.NewWriter(f)
	_, _ = gw.Write([]byte("this is not valid tar data but is long enough to trigger an error"))
	_ = gw.Close()
	_ = f.Close()

	if err := extractBinary(path, filepath.Join(dir, "out")); err == nil {
		t.Fatal("expected error for corrupt tar")
	}
}

func TestExtractBinary_OpenError(t *testing.T) {
	if err := extractBinary("/nonexistent/archive.tar.gz", "/tmp/out"); err == nil {
		t.Fatal("expected error for missing archive")
	}
}

func TestExtractBinary_InvalidDest(t *testing.T) {
	content := []byte("binary")
	archivePath := createTestTarGz(t, map[string][]byte{"litesoc-agent": content})

	if err := extractBinary(archivePath, "/nonexistent/dir/litesoc-agent"); err == nil {
		t.Fatal("expected error for invalid dest directory")
	}
}

// ============================================
// copyFile
// ============================================

func TestCopyFile_Success(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	content := []byte("file content here")
	_ = os.WriteFile(src, content, 0644)

	if err := copyFile(src, dst); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, _ := os.ReadFile(dst)
	if string(got) != string(content) {
		t.Errorf("content = %q; want %q", got, content)
	}
}

func TestCopyFile_SourceMissing(t *testing.T) {
	if err := copyFile("/nonexistent/src", filepath.Join(t.TempDir(), "dst")); err == nil {
		t.Fatal("expected error for missing source")
	}
}

func TestCopyFile_InvalidDest(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	_ = os.WriteFile(src, []byte("x"), 0644)

	if err := copyFile(src, "/nonexistent/dir/dst"); err == nil {
		t.Fatal("expected error for invalid dest directory")
	}
}

// ============================================
// selfUpdate
// ============================================

func TestSelfUpdate_NilInfo(t *testing.T) {
	err := selfUpdate(nil)
	if err == nil {
		t.Fatal("expected error for nil info")
	}
	if !strings.Contains(err.Error(), "missing download URL") {
		t.Errorf("error = %v; want 'missing download URL'", err)
	}
}

func TestSelfUpdate_EmptyURL(t *testing.T) {
	err := selfUpdate(&updateInfo{Available: true})
	if err == nil {
		t.Fatal("expected error for empty download URL")
	}
}

func TestSelfUpdate_FullSuccess(t *testing.T) {
	stubUpdaterVars(t)

	binaryContent := []byte("#!/bin/sh\necho updated")
	archivePath := createTestTarGz(t, map[string][]byte{"litesoc-agent": binaryContent})
	hash := sha256File(t, archivePath)
	archiveName := fmt.Sprintf("litesoc-agent_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)

	mux := http.NewServeMux()
	mux.HandleFunc("/agent.tar.gz", func(w http.ResponseWriter, r *http.Request) {
		data, _ := os.ReadFile(archivePath)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/checksums.sha256", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  %s\n", hash, archiveName)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	destBinary := filepath.Join(t.TempDir(), "litesoc-agent")
	_ = os.WriteFile(destBinary, []byte("old"), 0755)

	osExecutable = func() (string, error) { return destBinary, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }
	installBinary = func(stage, dest string) error { return copyFile(stage, dest) }
	restartService = func() error { return nil }

	info := &updateInfo{
		Available:     true,
		LatestVersion: "2.0.0",
		DownloadURL:   srv.URL + "/agent.tar.gz",
		ChecksumURL:   srv.URL + "/checksums.sha256",
		Force:         true,
	}
	if err := selfUpdate(info); err != nil {
		t.Fatalf("selfUpdate error: %v", err)
	}

	// Verify the binary was replaced.
	got, _ := os.ReadFile(destBinary)
	if string(got) != string(binaryContent) {
		t.Errorf("binary content = %q; want %q", got, binaryContent)
	}
}

func TestSelfUpdate_NoChecksumURL(t *testing.T) {
	stubUpdaterVars(t)

	binaryContent := []byte("bin")
	archivePath := createTestTarGz(t, map[string][]byte{"litesoc-agent": binaryContent})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := os.ReadFile(archivePath)
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	destBinary := filepath.Join(t.TempDir(), "litesoc-agent")
	_ = os.WriteFile(destBinary, []byte("old"), 0755)

	osExecutable = func() (string, error) { return destBinary, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }
	installBinary = func(stage, dest string) error { return copyFile(stage, dest) }
	restartService = func() error { return nil }

	info := &updateInfo{
		Available:     true,
		LatestVersion: "2.0.0",
		DownloadURL:   srv.URL,
		ChecksumURL:   "", // no checksum
	}
	if err := selfUpdate(info); err != nil {
		t.Fatalf("selfUpdate error: %v", err)
	}
}

func TestSelfUpdate_DownloadError(t *testing.T) {
	info := &updateInfo{
		Available:     true,
		LatestVersion: "2.0.0",
		DownloadURL:   "http://127.0.0.1:1/agent.tar.gz",
	}

	err := selfUpdate(info)
	if err == nil {
		t.Fatal("expected download error")
	}
	if !strings.Contains(err.Error(), "download archive") {
		t.Errorf("error = %v; want 'download archive'", err)
	}
}

func TestSelfUpdate_ChecksumError(t *testing.T) {
	archivePath := createTestTarGz(t, map[string][]byte{"litesoc-agent": []byte("bin")})
	archiveName := fmt.Sprintf("litesoc-agent_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)

	mux := http.NewServeMux()
	mux.HandleFunc("/agent.tar.gz", func(w http.ResponseWriter, r *http.Request) {
		data, _ := os.ReadFile(archivePath)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/checksums.sha256", func(w http.ResponseWriter, r *http.Request) {
		// Wrong hash
		fmt.Fprintf(w, "0000000000000000000000000000000000000000000000000000000000000000  %s\n", archiveName)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	info := &updateInfo{
		Available:     true,
		LatestVersion: "2.0.0",
		DownloadURL:   srv.URL + "/agent.tar.gz",
		ChecksumURL:   srv.URL + "/checksums.sha256",
	}

	err := selfUpdate(info)
	if err == nil {
		t.Fatal("expected checksum error")
	}
	if !strings.Contains(err.Error(), "checksum") {
		t.Errorf("error = %v; want 'checksum'", err)
	}
}

func TestSelfUpdate_ExtractError(t *testing.T) {
	// Archive with no litesoc-agent binary → extract fails.
	archivePath := createTestTarGz(t, map[string][]byte{"README.md": []byte("readme")})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := os.ReadFile(archivePath)
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	info := &updateInfo{
		Available:     true,
		LatestVersion: "2.0.0",
		DownloadURL:   srv.URL,
	}

	err := selfUpdate(info)
	if err == nil {
		t.Fatal("expected extract error")
	}
	if !strings.Contains(err.Error(), "extract binary") {
		t.Errorf("error = %v; want 'extract binary'", err)
	}
}

func TestSelfUpdate_ExecutableError(t *testing.T) {
	stubUpdaterVars(t)

	binaryContent := []byte("bin")
	archivePath := createTestTarGz(t, map[string][]byte{"litesoc-agent": binaryContent})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := os.ReadFile(archivePath)
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	osExecutable = func() (string, error) { return "", fmt.Errorf("executable error") }
	installBinary = func(_, _ string) error { return nil }
	restartService = func() error { return nil }

	info := &updateInfo{Available: true, LatestVersion: "2.0.0", DownloadURL: srv.URL}
	err := selfUpdate(info)
	if err == nil {
		t.Fatal("expected executable error")
	}
	if !strings.Contains(err.Error(), "resolve current binary path") {
		t.Errorf("error = %v; want 'resolve current binary path'", err)
	}
}

func TestSelfUpdate_SymlinkError(t *testing.T) {
	stubUpdaterVars(t)

	binaryContent := []byte("bin")
	archivePath := createTestTarGz(t, map[string][]byte{"litesoc-agent": binaryContent})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := os.ReadFile(archivePath)
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	osExecutable = func() (string, error) { return "/tmp/test-bin", nil }
	evalSymlinks = func(_ string) (string, error) { return "", fmt.Errorf("symlink error") }
	installBinary = func(_, _ string) error { return nil }
	restartService = func() error { return nil }

	info := &updateInfo{Available: true, LatestVersion: "2.0.0", DownloadURL: srv.URL}
	err := selfUpdate(info)
	if err == nil {
		t.Fatal("expected symlink error")
	}
	if !strings.Contains(err.Error(), "resolve symlinks") {
		t.Errorf("error = %v; want 'resolve symlinks'", err)
	}
}

func TestSelfUpdate_InstallError(t *testing.T) {
	stubUpdaterVars(t)

	binaryContent := []byte("bin")
	archivePath := createTestTarGz(t, map[string][]byte{"litesoc-agent": binaryContent})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := os.ReadFile(archivePath)
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	osExecutable = func() (string, error) { return "/tmp/test-bin", nil }
	evalSymlinks = func(p string) (string, error) { return p, nil }
	installBinary = func(_, _ string) error { return fmt.Errorf("permission denied") }
	restartService = func() error { return nil }

	info := &updateInfo{Available: true, LatestVersion: "2.0.0", DownloadURL: srv.URL}
	err := selfUpdate(info)
	if err == nil {
		t.Fatal("expected install error")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("error = %v; want 'permission denied'", err)
	}
}

func TestSelfUpdate_RestartError(t *testing.T) {
	stubUpdaterVars(t)

	binaryContent := []byte("bin")
	archivePath := createTestTarGz(t, map[string][]byte{"litesoc-agent": binaryContent})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := os.ReadFile(archivePath)
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	destBinary := filepath.Join(t.TempDir(), "litesoc-agent")
	_ = os.WriteFile(destBinary, []byte("old"), 0755)

	osExecutable = func() (string, error) { return destBinary, nil }
	evalSymlinks = func(p string) (string, error) { return p, nil }
	installBinary = func(stage, dest string) error { return copyFile(stage, dest) }
	restartService = func() error { return fmt.Errorf("systemctl not found") }

	info := &updateInfo{Available: true, LatestVersion: "2.0.0", DownloadURL: srv.URL}
	err := selfUpdate(info)
	if err == nil {
		t.Fatal("expected restart error")
	}
	if !strings.Contains(err.Error(), "systemctl") {
		t.Errorf("error = %v; want 'systemctl'", err)
	}
}

// ============================================
// Edge-case tests for io error paths
// ============================================

func TestCopyFile_ReadError(t *testing.T) {
	// Using a directory as source: os.Open succeeds but Read() returns EISDIR.
	dir := t.TempDir()
	dst := filepath.Join(dir, "dst")

	err := copyFile(dir, dst)
	if err == nil {
		t.Fatal("expected error when reading directory as file")
	}
}

func TestVerifyChecksum_ReadBodyError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Custom client whose body always errors on Read.
	client := &http.Client{
		Transport: &errBodyTransport{inner: srv.Client().Transport},
	}

	err := verifyChecksum(client, srv.URL, "/tmp/any")
	if err == nil {
		t.Fatal("expected body read error")
	}
	if !strings.Contains(err.Error(), "read checksums") {
		t.Errorf("error = %v; want 'read checksums'", err)
	}
}

func TestVerifyChecksum_HashCopyError(t *testing.T) {
	// archivePath is a directory → os.Open succeeds, io.Copy(hasher, dirFd) fails.
	dir := t.TempDir()
	archiveName := fmt.Sprintf("litesoc-agent_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abcd  %s\n", archiveName)
	}))
	defer srv.Close()

	err := verifyChecksum(srv.Client(), srv.URL, dir)
	if err == nil {
		t.Fatal("expected hash copy error for directory fd")
	}
}

func TestExtractBinary_TruncatedEntry(t *testing.T) {
	// Create an archive where the tar header declares more bytes than exist,
	// causing io.Copy to return an unexpected EOF during extraction.
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "truncated.tar.gz")
	f, _ := os.Create(archivePath)
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	// Header says 8192 bytes but we only write 64.
	_ = tw.WriteHeader(&tar.Header{
		Name:     "litesoc-agent",
		Size:     8192,
		Mode:     0755,
		Typeflag: tar.TypeReg,
	})
	_, _ = tw.Write(make([]byte, 64))
	// Intentionally close despite the size mismatch — file is on disk.
	_ = tw.Close()
	_ = gw.Close()
	_ = f.Close()

	destPath := filepath.Join(dir, "out")
	err := extractBinary(archivePath, destPath)
	if err == nil {
		t.Fatal("expected error for truncated tar entry")
	}
}
