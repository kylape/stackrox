package utils

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// FileUtils provides file operation utilities
type FileUtils struct{}

// NewFileUtils creates a new FileUtils instance
func NewFileUtils() *FileUtils {
	return &FileUtils{}
}

// Exists checks if a file or directory exists
func (f *FileUtils) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// IsDir checks if the path is a directory
func (f *FileUtils) IsDir(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// IsFile checks if the path is a regular file
func (f *FileUtils) IsFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular()
}

// EnsureDir ensures a directory exists, creating it if necessary
func (f *FileUtils) EnsureDir(path string) error {
	if f.Exists(path) {
		if !f.IsDir(path) {
			return fmt.Errorf("path %s exists but is not a directory", path)
		}
		return nil
	}
	
	return os.MkdirAll(path, 0755)
}

// EnsureParentDir ensures the parent directory of a file path exists
func (f *FileUtils) EnsureParentDir(filePath string) error {
	parentDir := filepath.Dir(filePath)
	return f.EnsureDir(parentDir)
}

// CreateTempDir creates a temporary directory
func (f *FileUtils) CreateTempDir(prefix string) (string, error) {
	return os.MkdirTemp("", prefix)
}

// CreateTempFile creates a temporary file
func (f *FileUtils) CreateTempFile(prefix, suffix string) (*os.File, error) {
	return os.CreateTemp("", prefix+"*"+suffix)
}

// CopyFile copies a file from src to dst
func (f *FileUtils) CopyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file %s: %w", src, err)
	}
	defer sourceFile.Close()

	// Ensure destination directory exists
	if err := f.EnsureParentDir(dst); err != nil {
		return fmt.Errorf("failed to ensure parent directory: %w", err)
	}

	destinationFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file %s: %w", dst, err)
	}
	defer destinationFile.Close()

	_, err = io.Copy(destinationFile, sourceFile)
	if err != nil {
		return fmt.Errorf("failed to copy file content: %w", err)
	}

	// Copy file permissions
	sourceInfo, err := sourceFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to get source file info: %w", err)
	}

	err = os.Chmod(dst, sourceInfo.Mode())
	if err != nil {
		return fmt.Errorf("failed to set file permissions: %w", err)
	}

	return nil
}

// CopyDir recursively copies a directory from src to dst
func (f *FileUtils) CopyDir(src, dst string) error {
	sourceInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("failed to stat source directory %s: %w", src, err)
	}

	if !sourceInfo.IsDir() {
		return fmt.Errorf("source %s is not a directory", src)
	}

	// Create destination directory
	if err := os.MkdirAll(dst, sourceInfo.Mode()); err != nil {
		return fmt.Errorf("failed to create destination directory %s: %w", dst, err)
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return fmt.Errorf("failed to read directory %s: %w", src, err)
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			err = f.CopyDir(srcPath, dstPath)
		} else {
			err = f.CopyFile(srcPath, dstPath)
		}

		if err != nil {
			return fmt.Errorf("failed to copy %s: %w", srcPath, err)
		}
	}

	return nil
}

// RemoveAll removes a file or directory and all its contents
func (f *FileUtils) RemoveAll(path string) error {
	return os.RemoveAll(path)
}

// ReadFile reads the entire content of a file
func (f *FileUtils) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// ReadFileString reads the entire content of a file as a string
func (f *FileUtils) ReadFileString(path string) (string, error) {
	data, err := f.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// WriteFile writes data to a file
func (f *FileUtils) WriteFile(path string, data []byte, perm os.FileMode) error {
	if err := f.EnsureParentDir(path); err != nil {
		return fmt.Errorf("failed to ensure parent directory: %w", err)
	}
	return os.WriteFile(path, data, perm)
}

// WriteFileString writes a string to a file
func (f *FileUtils) WriteFileString(path, content string, perm os.FileMode) error {
	return f.WriteFile(path, []byte(content), perm)
}

// AppendToFile appends data to a file
func (f *FileUtils) AppendToFile(path string, data []byte) error {
	if err := f.EnsureParentDir(path); err != nil {
		return fmt.Errorf("failed to ensure parent directory: %w", err)
	}

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file for appending: %w", err)
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}

	return nil
}

// AppendStringToFile appends a string to a file
func (f *FileUtils) AppendStringToFile(path, content string) error {
	return f.AppendToFile(path, []byte(content))
}

// FindFiles finds files matching a pattern in a directory
func (f *FileUtils) FindFiles(dir, pattern string) ([]string, error) {
	var matches []string
	
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		
		if d.IsDir() {
			return nil
		}
		
		matched, err := filepath.Match(pattern, filepath.Base(path))
		if err != nil {
			return err
		}
		
		if matched {
			matches = append(matches, path)
		}
		
		return nil
	})
	
	return matches, err
}

// GetFileSize returns the size of a file in bytes
func (f *FileUtils) GetFileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("failed to stat file %s: %w", path, err)
	}
	return info.Size(), nil
}

// GetFileMode returns the file mode/permissions
func (f *FileUtils) GetFileMode(path string) (os.FileMode, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("failed to stat file %s: %w", path, err)
	}
	return info.Mode(), nil
}

// SetFileMode sets the file mode/permissions
func (f *FileUtils) SetFileMode(path string, mode os.FileMode) error {
	return os.Chmod(path, mode)
}

// ExpandPath expands ~ to the user's home directory
func (f *FileUtils) ExpandPath(path string) (string, error) {
	if path == "" {
		return path, nil
	}
	
	if path[0] != '~' {
		return path, nil
	}
	
	if len(path) == 1 || path[1] == '/' {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get user home directory: %w", err)
		}
		return filepath.Join(home, path[1:]), nil
	}
	
	// Handle ~user/path format (not implemented)
	return "", fmt.Errorf("~user expansion not supported")
}

// RelativePath returns the relative path from base to target
func (f *FileUtils) RelativePath(base, target string) (string, error) {
	return filepath.Rel(base, target)
}

// AbsolutePath returns the absolute path
func (f *FileUtils) AbsolutePath(path string) (string, error) {
	expanded, err := f.ExpandPath(path)
	if err != nil {
		return "", err
	}
	return filepath.Abs(expanded)
}

// JoinPath joins path elements
func (f *FileUtils) JoinPath(elements ...string) string {
	return filepath.Join(elements...)
}

// SplitPath splits a path into directory and file
func (f *FileUtils) SplitPath(path string) (dir, file string) {
	return filepath.Split(path)
}

// GetExtension returns the file extension
func (f *FileUtils) GetExtension(path string) string {
	return filepath.Ext(path)
}

// ChangeExtension changes the file extension
func (f *FileUtils) ChangeExtension(path, newExt string) string {
	if !strings.HasPrefix(newExt, ".") {
		newExt = "." + newExt
	}
	return strings.TrimSuffix(path, filepath.Ext(path)) + newExt
}

// ListDir lists the contents of a directory
func (f *FileUtils) ListDir(dir string) ([]os.DirEntry, error) {
	return os.ReadDir(dir)
}

// GetCurrentDir returns the current working directory
func (f *FileUtils) GetCurrentDir() (string, error) {
	return os.Getwd()
}

// ChangeDir changes the current working directory
func (f *FileUtils) ChangeDir(dir string) error {
	return os.Chdir(dir)
}

// CreateSymlink creates a symbolic link
func (f *FileUtils) CreateSymlink(target, link string) error {
	if err := f.EnsureParentDir(link); err != nil {
		return fmt.Errorf("failed to ensure parent directory: %w", err)
	}
	return os.Symlink(target, link)
}

// ReadSymlink reads the target of a symbolic link
func (f *FileUtils) ReadSymlink(link string) (string, error) {
	return os.Readlink(link)
}

// IsSymlink checks if a path is a symbolic link
func (f *FileUtils) IsSymlink(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeSymlink != 0
}