package fileutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Replace atomically publishes temporaryPath at destinationPath. Both paths
// must be in the same directory. The fallback preserves the old destination on
// platforms where os.Rename cannot replace an existing file.
func Replace(temporaryPath, destinationPath string) error {
	temporaryDirectory, err := filepath.Abs(filepath.Dir(temporaryPath))
	if err != nil {
		return fmt.Errorf("resolve temporary directory: %w", err)
	}
	destinationDirectory, err := filepath.Abs(filepath.Dir(destinationPath))
	if err != nil {
		return fmt.Errorf("resolve destination directory: %w", err)
	}
	if temporaryDirectory != destinationDirectory {
		return errors.New("temporary and destination files must share a directory")
	}

	if err := os.Rename(temporaryPath, destinationPath); err == nil {
		return nil
	} else if _, statErr := os.Stat(destinationPath); statErr != nil {
		return fmt.Errorf("publish %s: %w", destinationPath, err)
	}

	backup, err := os.CreateTemp(destinationDirectory, ".anyapi-backup-*.tmp")
	if err != nil {
		return fmt.Errorf("reserve replacement backup: %w", err)
	}
	backupPath := backup.Name()
	if err := backup.Close(); err != nil {
		_ = os.Remove(backupPath)
		return fmt.Errorf("close replacement backup: %w", err)
	}
	if err := os.Remove(backupPath); err != nil {
		return fmt.Errorf("prepare replacement backup: %w", err)
	}
	if err := os.Rename(destinationPath, backupPath); err != nil {
		return fmt.Errorf("preserve existing %s: %w", destinationPath, err)
	}
	if err := os.Rename(temporaryPath, destinationPath); err != nil {
		restoreErr := os.Rename(backupPath, destinationPath)
		if restoreErr != nil {
			return fmt.Errorf("publish %s: %w; restoring original also failed: %v", destinationPath, err, restoreErr)
		}
		return fmt.Errorf("publish %s: %w", destinationPath, err)
	}
	if err := os.Remove(backupPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove replacement backup: %w", err)
	}
	return nil
}
