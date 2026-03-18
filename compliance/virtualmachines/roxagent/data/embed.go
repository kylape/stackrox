package data

import (
	_ "embed"
	"os"
	"path/filepath"
)

//go:embed repo-to-cpe-fallback.json
var RepoToCPEFallback []byte

// WriteFallbackFile writes the embedded CPE mapping to a temporary file
// and returns its path. The caller should clean up the file when done.
func WriteFallbackFile() (string, error) {
	tmpDir := os.TempDir()
	path := filepath.Join(tmpDir, "repo-to-cpe-fallback.json")
	if err := os.WriteFile(path, RepoToCPEFallback, 0644); err != nil {
		return "", err
	}
	return path, nil
}
