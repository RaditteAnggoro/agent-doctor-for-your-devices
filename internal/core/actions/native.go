package actions

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/platforms"
)

type nativeBackend struct{}

func Native() Backend { return nativeBackend{} }
func (nativeBackend) Available() error {
	switch runtime.GOOS {
	case "darwin":
		if platforms.Tool("osascript") != "" {
			return nil
		}

	}
	return errors.New("UNSUPPORTED: no verified native Trash backend available; use OS/vendor UI manually")
}

// Foundation's trashItemAtURL has no permanent-delete fallback. The selected
// path is passed as argv data, never interpolated into executable script source.
// File-reference URLs retain identity across path renames on supported volumes.
const macTrashScript = `use framework "Foundation"
on run argv
 if (count of argv) is not 2 then error "Expected path and filesystem identity"
 set manager to current application's NSFileManager's defaultManager()
 set fileURL to current application's NSURL's fileURLWithPath:(item 1 of argv)
 set referenceURL to fileURL's fileReferenceURL()
 if referenceURL is missing value then error "File-reference URL unavailable"
 set {attributes, attributesError} to manager's attributesOfItemAtPath:(referenceURL's |path|()) |error|:(reference)
 if attributes is missing value then error "Target attributes unavailable"
 set deviceNumber to ((attributes's objectForKey:(current application's NSFileSystemNumber))'s stringValue()) as text
 set inodeNumber to ((attributes's objectForKey:(current application's NSFileSystemFileNumber))'s stringValue()) as text
 if (deviceNumber & ":" & inodeNumber) is not (item 2 of argv) then error "Target identity changed; no action"
 set {succeeded, resultingURL, trashError} to manager's trashItemAtURL:referenceURL resultingItemURL:(reference) |error|:(reference)
 if not (succeeded as boolean) then error "Native Trash refused operation"
 return (resultingURL's |path|()) as text
end run`

func (nativeBackend) Trash(ctx context.Context, f Fingerprint) (string, error) {
	switch runtime.GOOS {
	case "darwin":
		b, e := platforms.Run(ctx, "osascript", "-e", macTrashScript, f.Path, f.Identity)
		if e != nil {
			return "", e
		}
		destination := strings.TrimSuffix(string(b), "\n")
		if !filepath.IsAbs(destination) || destination == f.Path {
			return "", errors.New("invalid native Trash destination")
		}
		return destination, nil
	case "linux":
		return "", errors.New("UNSUPPORTED: identity-preserving Linux Trash execution has not been verified; use the OS UI")
	}
	return "", fmt.Errorf("UNSUPPORTED: native Trash for %s", runtime.GOOS)
}
