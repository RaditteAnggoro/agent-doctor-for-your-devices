//go:build !darwin && !linux

package safety

import "os"

// Portable SameFile checks still deduplicate hardlinks. Physical allocation and
// device identities are unavailable here, so their values remain unknown.
func Identity(info os.FileInfo) (string, string, bool, *bool) { return "", "", false, nil }

// Native Windows scans are constrained by the current user's access token.
// Ownership attribution is not available in this portable collector.
func Owned(info os.FileInfo) bool { return true }
