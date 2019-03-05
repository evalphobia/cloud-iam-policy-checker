package checker

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
)

// FileHandler handles CSV file.
type FileHandler struct {
	separator rune
	fp        *os.File
}

// NewFileHandler returns initialized *FileHandler
func NewFileHandler(file string) (*FileHandler, error) {
	if err := checkIsDir(file); err != nil {
		return nil, err
	}

	// load file
	fp, err := os.Create(file)
	if err != nil {
		return nil, err
	}

	f := &FileHandler{
		fp: fp,
	}

	switch filepath.Ext(file) {
	case ".tsv":
		f.separator = '\t'
	}

	return f, nil
}

// WriteAll writes lines into file
func (f *FileHandler) WriteAll(header []string, lines [][]string) error {
	defer f.fp.Close()

	w := csv.NewWriter(f.fp)
	if f.separator != rune(0) {
		w.Comma = f.separator
	}

	if err := w.Write(header); err != nil {
		return err
	}
	if err := w.WriteAll(lines); err != nil {
		return err
	}
	w.Flush()
	return nil
}

// checkIsDir checks if the given file path is directory.
func checkIsDir(filePath string) error {
	info, err := os.Stat(filePath)
	if err == nil && info.IsDir() {
		return fmt.Errorf("'%s' is dir, please set file path", filePath)
	}
	return nil
}
