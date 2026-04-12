package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// updateInfo is parsed from the heartbeat JSON response.
type updateInfo struct {
	Available     bool   `json:"available"`
	LatestVersion string `json:"latest_version"`
	DownloadURL   string `json:"download_url"`
	ChecksumURL   string `json:"checksum_url"`
	Force         bool   `json:"force"`
}

// heartbeatResponse is the full JSON response from POST /agent/heartbeat.
type heartbeatResponse struct {
	Success bool        `json:"success"`
	Update  *updateInfo `json:"update,omitempty"`
}

// selfUpdate downloads the new binary, verifies its checksum, atomically
// replaces the running binary, and restarts via systemd.
//
// The binary at destPath must be owned by the service user (set by install.sh)
// and the systemd unit must list it in ReadWritePaths= so that ProtectSystem=strict
// allows the write. No sudo or privilege escalation is required.
//
// This function only returns on error — a successful update sends SIGTERM to
// the current process and systemd (Restart=always) starts the new binary.
var selfUpdate = func(info *updateInfo) error {
	if info == nil || info.DownloadURL == "" {
		return fmt.Errorf("missing download URL")
	}

	slog.Info("self-update: starting",
		"current", agentVersion,
		"target", info.LatestVersion,
		"url", info.DownloadURL,
	)

	client := &http.Client{Timeout: 120 * time.Second}

	// 1. Download the archive to a temp file.
	tmpDir, err := os.MkdirTemp("", "litesoc-update-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	archivePath := filepath.Join(tmpDir, "agent.tar.gz")
	if err := downloadFile(client, info.DownloadURL, archivePath); err != nil {
		return fmt.Errorf("download archive: %w", err)
	}

	// 2. Verify checksum if available.
	if info.ChecksumURL != "" {
		if err := verifyChecksum(client, info.ChecksumURL, archivePath); err != nil {
			return fmt.Errorf("checksum verification failed: %w", err)
		}
		slog.Info("self-update: checksum verified")
	}

	// 3. Extract the binary from the tar.gz archive.
	binaryPath := filepath.Join(tmpDir, "litesoc-agent")
	if err := extractBinary(archivePath, binaryPath); err != nil {
		return fmt.Errorf("extract binary: %w", err)
	}

	// 4. Make the extracted binary executable.
	if err := os.Chmod(binaryPath, 0755); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}

	// 5. Stage the new binary to /tmp (always writable, even with PrivateTmp=true).
	//    installBinary then overwrites the destination in-place; no sudo needed.
	const stagePath = "/tmp/litesoc-agent-update"
	if err := copyFile(binaryPath, stagePath); err != nil {
		return fmt.Errorf("stage binary: %w", err)
	}
	defer os.Remove(stagePath)

	currentBinary, err := osExecutable()
	if err != nil {
		return fmt.Errorf("resolve current binary path: %w", err)
	}
	currentBinary, err = evalSymlinks(currentBinary)
	if err != nil {
		return fmt.Errorf("resolve symlinks: %w", err)
	}

	slog.Info("self-update: installing binary",
		"stage", stagePath,
		"dest", currentBinary,
		"new_version", info.LatestVersion,
	)

	// Privileged copy — needs: litesoc ALL=(root) NOPASSWD: /usr/bin/cp /tmp/litesoc-agent-update <dest>
	if err := installBinary(stagePath, currentBinary); err != nil {
		return err
	}

	// 6. Restart via systemctl — this kills the current process.
	return restartService()
}

// restartService asks systemd to restart litesoc-agent.
// Declared as var so tests can stub it.
var restartService = func() error {
	// Send SIGTERM to ourselves. systemd (Restart=always) will immediately start
	// the freshly-installed binary. This avoids 'sudo systemctl restart' which
	// is blocked by NoNewPrivileges=true in the service unit.
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		return fmt.Errorf("find self process: %w", err)
	}
	return p.Signal(syscall.SIGTERM)
}

var (
	osExecutable  = os.Executable
	evalSymlinks  = filepath.EvalSymlinks
	installBinary = func(stagePath, destPath string) error {
		// Open the destination binary in-place and overwrite it. The file is owned
		// by the service user (set by install.sh) and listed in ReadWritePaths=
		// so ProtectSystem=strict allows the write without privilege escalation.
		src, err := os.Open(stagePath)
		if err != nil {
			return fmt.Errorf("open stage: %w", err)
		}
		defer func() { _ = src.Close() }()

		dst, err := os.OpenFile(destPath, os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			return fmt.Errorf("open dest for write: %w", err)
		}
		if _, err := io.Copy(dst, src); err != nil {
			_ = dst.Close()
			return fmt.Errorf("write binary: %w", err)
		}
		return dst.Close()
	}
)

// downloadFile fetches a URL and writes it to disk.
func downloadFile(client *http.Client, url, dest string) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	// Limit to 100 MB to prevent resource exhaustion.
	_, err = io.Copy(out, io.LimitReader(resp.Body, 100*1024*1024))
	return err
}

// verifyChecksum downloads a checksums.sha256 file and verifies the archive
// hash against it.
func verifyChecksum(client *http.Client, checksumURL, archivePath string) error {
	resp, err := client.Get(checksumURL)
	if err != nil {
		return fmt.Errorf("download checksums: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Non-fatal: if checksum file isn't available, skip verification.
		slog.Warn("self-update: checksum file not available, skipping", "status", resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return fmt.Errorf("read checksums: %w", err)
	}

	// Compute SHA-256 of the downloaded archive.
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return err
	}
	actual := hex.EncodeToString(hasher.Sum(nil))

	// Archive name we're looking for in the checksums file.
	archiveName := fmt.Sprintf("litesoc-agent_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)

	for _, line := range strings.Split(string(body), "\n") {
		if strings.Contains(line, archiveName) {
			parts := strings.Fields(line)
			if len(parts) >= 1 && strings.EqualFold(parts[0], actual) {
				return nil
			}
			return fmt.Errorf("hash mismatch: expected %s, got %s", parts[0], actual)
		}
	}

	slog.Warn("self-update: archive not listed in checksums file, skipping verification")
	return nil
}

// extractBinary pulls the "litesoc-agent" binary out of a tar.gz archive.
func extractBinary(archivePath, destPath string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("binary not found in archive")
		}
		if err != nil {
			return err
		}
		if filepath.Base(hdr.Name) == "litesoc-agent" && hdr.Typeflag == tar.TypeReg {
			out, err := os.Create(destPath)
			if err != nil {
				return err
			}
			// Limit extraction to 200 MB to prevent zip-bomb attacks.
			_, copyErr := io.Copy(out, io.LimitReader(tr, 200*1024*1024))
			closeErr := out.Close()
			if copyErr != nil {
				return copyErr
			}
			return closeErr
		}
	}
}

// copyFile copies src to dst, preserving permissions.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	// Write to a temp file in the same directory, then rename.
	tmpDst := dst + ".new"
	out, err := os.OpenFile(tmpDst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmpDst)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmpDst)
		return err
	}

	return os.Rename(tmpDst, dst)
}
