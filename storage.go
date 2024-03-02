package graphify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
)

// IFileStorage ...
type IFileStorage interface {
	// StoreFile ...
	StoreFile(file multipart.File, header *multipart.FileHeader) (hash string, err error)

	// ReadFile ...
	ReadFile(hash string) (fileContent []byte, errr error)

	// MaxMemory ...
	MaxMemory() int64
}

// filesystemStorage ...
type filesystemStorage struct {
	basePath  string
	maxMemory int64
}

// NewFilesystemStorage ...
func NewFilesystemStorage(basePath string, maxMemory int64) *filesystemStorage {
	return &filesystemStorage{basePath: basePath, maxMemory: maxMemory}
}

func (s *filesystemStorage) StoreFile(file multipart.File, handler *multipart.FileHeader) (string, error) {
	// Create the upload directory if it doesn't exist
	if _, err := os.Stat(s.basePath); os.IsNotExist(err) {
		os.Mkdir(s.basePath, os.ModePerm)
	}

	// Read the file
	var buffer bytes.Buffer
	_, err := io.Copy(&buffer, file)
	if err != nil {
		return "", err
	}

	// Calculate file hash
	hasher := sha256.New()
	if _, err := hasher.Write(buffer.Bytes()); err != nil {
		return "", err
	}
	hashInBytes := hasher.Sum(nil)
	hash := hex.EncodeToString(hashInBytes)

	// Write file to system
	filename := filepath.Join(s.basePath, hash)
	out, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer out.Close()

	// Copy file data
	if err := os.WriteFile(filename, buffer.Bytes(), 0644); err != nil {
		return "", err
	}

	return hash, nil
}

func (s *filesystemStorage) ReadFile(hash string) ([]byte, error) {
	filepath := filepath.Join(s.basePath, hash)

	// Check if the file exists
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		return nil, err
	}

	// Read the file content into a byte slice
	return os.ReadFile(filepath)
}

func (s *filesystemStorage) MaxMemory() int64 {
	return s.maxMemory
}
