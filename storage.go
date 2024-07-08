package graphify

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
)

// IFileStorage ...
type IFileStorage interface {
	// StoreFile ...
	StoreFile(name string, file []byte) (err error)

	// StoreByHash ...
	StoreByHash(file []byte) (hash string, err error)

	// ReadFile ...
	ReadFile(name string) (fileContent []byte, errr error)

	// MaxMemory ...
	MaxMemory() int
}

// filesystemStorage ...
type filesystemStorage struct {
	basePath  string
	maxMemory int
}

// FilesystemStorageConfig ...
type FilesystemStorageConfig struct {
	// BasePath ...
	BasePath string
	// MaxMemory ...
	MaxMemory int
}

// NewFilesystemStorage ...
func NewFilesystemStorage(params FilesystemStorageConfig) *filesystemStorage {
	return &filesystemStorage{basePath: params.BasePath, maxMemory: params.MaxMemory}
}

func (s *filesystemStorage) StoreFile(name string, file []byte) (err error) {
	// Create the upload directory if it doesn't exist
	if _, err := os.Stat(s.basePath); os.IsNotExist(err) {
		os.Mkdir(s.basePath, os.ModePerm)
	}

	// Write file to system
	filename := filepath.Join(s.basePath, name)
	out, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer out.Close()

	// Copy file data
	if err := os.WriteFile(filename, file, 0644); err != nil {
		return err
	}

	return nil
}

func (s *filesystemStorage) StoreByHash(file []byte) (string, error) {
	// Calculate file hash
	hasher := sha256.New()
	if _, err := hasher.Write(file); err != nil {
		return "", err
	}
	hashInBytes := hasher.Sum(nil)
	hash := hex.EncodeToString(hashInBytes)

	// Store buffer bytes
	if err := s.StoreFile(hash, file); err != nil {
		return "", err
	}

	return hash, nil
}

func (s *filesystemStorage) ReadFile(name string) ([]byte, error) {
	filepath := filepath.Join(s.basePath, name)

	// Check if the file exists
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		return nil, err
	}

	// Read the file content into a byte slice
	return os.ReadFile(filepath)
}

func (s *filesystemStorage) MaxMemory() int {
	return s.maxMemory
}
