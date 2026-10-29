package duplicates

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/scanner"
)

type budgetReader struct {
	ctx       context.Context
	r         io.Reader
	remaining *int64
	read      *int64
}

func (b budgetReader) Read(p []byte) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	if *b.remaining <= 0 {
		return 0, fmt.Errorf("hash/verification byte budget reached")
	}
	if int64(len(p)) > *b.remaining {
		p = p[:*b.remaining]
	}
	n, err := b.r.Read(p)
	*b.remaining -= int64(n)
	*b.read += int64(n)
	return n, err
}
func unchanged(f *os.File, e scanner.Entry) bool {
	s, err := f.Stat()
	return err == nil && os.SameFile(s, e.Info) && s.Size() == e.Info.Size() && s.ModTime().Equal(e.Info.ModTime())
}
func Collect(ctx context.Context, inv *scanner.Inventory, maxBytes int64) findings.Result {
	r := findings.Result{Feature: "duplicates", Support: "SUPPORTED", Coverage: inv.Coverage, Findings: []findings.Finding{}, Warnings: append([]string{}, inv.Warnings...), CollectionMethod: "size grouping, sequential streaming SHA-256, full byte comparison; bounded 128KiB buffers"}
	r.Coverage.BytesRead = 0
	fail := func(msg string) {
		r.Coverage.Status = "PARTIAL"
		r.Support = "PARTIAL"
		if len(r.Warnings) < 50 {
			r.Warnings = append(r.Warnings, msg)
		}
	}
	sizes := map[int64][]scanner.Entry{}
	for _, e := range inv.Entries {
		sizes[e.File.Size] = append(sizes[e.File.Size], e)
	}
	groups := map[string][]scanner.Entry{}
	remaining := maxBytes
	sizeOrder := []int64{}
	for size := range sizes {
		sizeOrder = append(sizeOrder, size)
	}
	sort.Slice(sizeOrder, func(i, j int) bool { return sizeOrder[i] < sizeOrder[j] })
	for _, size := range sizeOrder {
		es := sizes[size]
		if len(es) < 2 {
			continue
		}
		unique := []scanner.Entry{}
		identities := map[string]bool{}
		unknownIdentities := 0
		for _, e := range es {
			if ctx.Err() != nil {
				r.Coverage.Status = "CANCELLED"
				r.Support = "PARTIAL"
				return r
			}
			same := false
			if e.File.Identity != "" {
				same = identities[e.File.Identity]
				identities[e.File.Identity] = true
			} else {
				// The portable fallback cannot derive inode/file ID from FileInfo. Bound
				// comparison work as well as IO and check cancellation inside the loop.
				if unknownIdentities >= 1024 {
					fail("identity-unavailable size bucket capped at 1024 members")
					r.Coverage.Skipped++
					continue
				}
				unknownIdentities++
				for _, u := range unique {
					if ctx.Err() != nil {
						r.Coverage.Status = "CANCELLED"
						r.Support = "PARTIAL"
						return r
					}
					if os.SameFile(e.Info, u.Info) {
						same = true
						break
					}
				}
			}
			if same {
				r.Coverage.Skipped++
				continue
			}
			unique = append(unique, e)
		}
		if len(unique) < 2 {
			continue
		}
		for _, e := range unique {
			if ctx.Err() != nil {
				r.Coverage.Status = "CANCELLED"
				r.Support = "PARTIAL"
				return r
			}
			if e.File.Size > remaining {
				fail("byte budget reached; unhashed files excluded from exact groups")
				continue
			}
			f, err := e.Open()
			if err != nil {
				fail(fmt.Sprintf("file unavailable or changed: %q", e.File.Path))
				r.Coverage.Inaccessible++
				continue
			}
			h := sha256.New()
			n, err := io.CopyBuffer(h, io.LimitReader(budgetReader{ctx, f, &remaining, &r.Coverage.BytesRead}, e.File.Size), make([]byte, 64*1024))
			valid := unchanged(f, e)
			_ = f.Close()
			if err != nil || n != e.File.Size || !valid {
				fail("incomplete or changed file excluded")
				continue
			}
			digest := hex.EncodeToString(h.Sum(nil))
			groups[digest] = append(groups[digest], e)
		}
	}
	digests := []string{}
	for d, es := range groups {
		if len(es) > 1 {
			digests = append(digests, d)
		}
	}
	sort.Strings(digests)
	for _, digest := range digests {
		es := groups[digest]
		sort.Slice(es, func(i, j int) bool { return es[i].File.Path < es[j].File.Path })
		verified := []scanner.Entry{es[0]}
		for _, e := range es[1:] {
			if ctx.Err() != nil {
				r.Coverage.Status = "CANCELLED"
				r.Support = "PARTIAL"
				return r
			}
			if e.File.Size > remaining/2 {
				fail("byte-comparison budget reached; group member omitted")
				continue
			}
			a, err := es[0].Open()
			if err != nil {
				fail("reference file changed")
				continue
			}
			b, err := e.Open()
			if err != nil {
				_ = a.Close()
				fail("member file changed")
				continue
			}
			equal := true
			left := e.File.Size
			aa := make([]byte, 64*1024)
			bb := make([]byte, 64*1024)
			for left > 0 {
				sz := int64(len(aa))
				if sz > left {
					sz = left
				}
				na, ea := io.ReadFull(budgetReader{ctx, a, &remaining, &r.Coverage.BytesRead}, aa[:sz])
				nb, eb := io.ReadFull(budgetReader{ctx, b, &remaining, &r.Coverage.BytesRead}, bb[:sz])
				if ea != nil || eb != nil || na != nb || !bytes.Equal(aa[:na], bb[:nb]) {
					equal = false
					break
				}
				left -= int64(na)
			}
			valid := unchanged(a, es[0]) && unchanged(b, e)
			_ = a.Close()
			_ = b.Close()
			if equal && valid {
				verified = append(verified, e)
			} else {
				fail("changed or unequal file excluded after verification")
			}
		}
		if len(verified) < 2 {
			continue
		}
		members := []findings.File{}
		paths := []string{}
		for _, e := range verified {
			members = append(members, e.File)
			paths = append(paths, e.File.Path)
		}
		r.Findings = append(r.Findings, findings.Finding{ID: fmt.Sprintf("D-%06d", len(r.Findings)+1), Feature: "duplicates", Title: "Exact content group", Paths: paths, Risk: "MODERATE", Confidence: "HIGH", Recommendation: "INSPECT", WhyFlagged: "Full streaming SHA-256 and byte comparison matched distinct files at collection time.", Evidence: []string{"SHA-256: " + digest, fmt.Sprintf("%d distinct files", len(members))}, Limitations: []string{"Physical savings unknown: sparse allocation, clones and snapshots may share storage.", "Known cloud/library paths are excluded; other sync or backup locations may be unrecognized.", "Concurrent writers can change files after this observation."}, PossibleConsequences: "Copies may be intentional backups or needed by different applications. Manual removal can propagate through sync.", ManualInspection: "Compare every path and its role in backups or applications. Keep all files in this tool; use the OS UI only after your own decision.", Duplicate: &findings.Duplicate{MatchType: "EXACT_CONTENT", HashAlgorithm: "SHA-256", Digest: digest, Members: members, SuggestedRetain: paths[0], RetainReason: "Lexicographically first path is a neutral review starting point; no preference based on unknown file purpose.", LogicalRedundantBytes: int64(len(members)-1) * members[0].Size, BackupWarning: "Backup and unrecognized sync ownership are unknown. Retain all files until reviewed."}})
	}
	if ctx.Err() != nil {
		r.Coverage.Status = "CANCELLED"
		r.Support = "PARTIAL"
	}
	if inv.Coverage.Status != "COMPLETED" {
		r.Support = "PARTIAL"
	}
	return r
}
