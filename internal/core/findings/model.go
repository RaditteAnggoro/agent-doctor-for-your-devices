package findings

import "time"

type Environment struct {
	OS           string   `json:"os"`
	HostOS       string   `json:"host_os"`
	Architecture string   `json:"architecture"`
	Type         string   `json:"type"`
	Remote       bool     `json:"remote"`
	OSVersion    string   `json:"os_version"`
	Tools        []string `json:"tools"`
	Limitations  []string `json:"limitations"`
}
type Scope struct {
	Roots      []string `json:"roots"`
	Exclusions []string `json:"exclusions"`
	MaxFiles   int      `json:"max_files"`
	MaxDepth   int      `json:"max_depth"`
	MaxBytes   int64    `json:"max_bytes"`
}
type File struct {
	Path     string    `json:"path"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
	Device   string    `json:"device"`
	Identity string    `json:"identity"`
	Hardlink *bool     `json:"hardlink"`
	Symlink  bool      `json:"symlink"`
	Sparse   *bool     `json:"sparse"`
	Clone    *bool     `json:"clone"`
	Cloud    bool      `json:"cloud"`
}
type Finding struct {
	ID                   string       `json:"id"`
	Feature              string       `json:"feature"`
	Title                string       `json:"title"`
	Paths                []string     `json:"paths"`
	Risk                 string       `json:"risk"`
	Confidence           string       `json:"confidence"`
	Recommendation       string       `json:"recommendation"`
	WhyFlagged           string       `json:"why_flagged"`
	Evidence             []string     `json:"evidence"`
	Limitations          []string     `json:"limitations"`
	PossibleConsequences string       `json:"possible_consequences"`
	ManualInspection     string       `json:"manual_inspection"`
	Junk                 *Junk        `json:"junk,omitempty"`
	Performance          *Performance `json:"performance,omitempty"`
	Application          *Application `json:"application,omitempty"`
	Duplicate            *Duplicate   `json:"duplicate,omitempty"`
}
type Junk struct {
	File             File       `json:"file"`
	Basename         string     `json:"basename"`
	Kind             string     `json:"kind"`
	Category         string     `json:"category"`
	ReclaimableBytes *int64     `json:"reclaimable_bytes"`
	LastAccessed     *time.Time `json:"last_accessed"`
	OwningApp        *string    `json:"owning_app"`
	ActiveUseHints   []string   `json:"active_use_hints"`
	Backup           bool       `json:"backup"`
	ReviewStatus     string     `json:"review_status"`
}
type Performance struct {
	PID                  *int     `json:"pid"`
	ProcessName          *string  `json:"process_name"`
	ExecutablePath       *string  `json:"executable_path"`
	CPUPercent           *float64 `json:"cpu_percent"`
	CPUSemantics         string   `json:"cpu_semantics"`
	RSSBytes             *int64   `json:"rss_bytes"`
	MemoryTotalBytes     *int64   `json:"memory_total_bytes"`
	MemoryAvailableBytes *int64   `json:"memory_available_bytes"`
	SwapUsedBytes        *int64   `json:"swap_used_bytes"`
	DiskTotalBytes       *int64   `json:"disk_total_bytes"`
	DiskAvailableBytes   *int64   `json:"disk_available_bytes"`
	ObservationSeconds   float64  `json:"observation_seconds"`
	StartupSource        *string  `json:"startup_source"`
	Owner                *string  `json:"owner"`
	Running              *bool    `json:"running"`
	DependencyNotes      string   `json:"dependency_notes"`
	ObservedImpact       string   `json:"observed_impact"`
}
type Application struct {
	Name             string     `json:"name"`
	Version          *string    `json:"version"`
	Location         *string    `json:"location"`
	Source           string     `json:"source"`
	InstallSizeBytes *int64     `json:"install_size_bytes"`
	SizeMethod       string     `json:"size_method"`
	LastUsage        *time.Time `json:"last_usage"`
	UsageProvenance  string     `json:"usage_provenance"`
	InstalledAt      *time.Time `json:"installed_at"`
	UpdatedAt        *time.Time `json:"updated_at"`
	Running          *bool      `json:"running"`
	RelatedServices  []string   `json:"related_services"`
	DependencyNotes  string     `json:"dependency_notes"`
	UninstallMethod  string     `json:"uninstall_method"`
}
type Duplicate struct {
	MatchType                string `json:"match_type"`
	HashAlgorithm            string `json:"hash_algorithm"`
	Digest                   string `json:"digest"`
	Members                  []File `json:"members"`
	SuggestedRetain          string `json:"suggested_retain"`
	RetainReason             string `json:"retain_reason"`
	LogicalRedundantBytes    int64  `json:"logical_redundant_bytes"`
	PhysicalReclaimableBytes *int64 `json:"physical_reclaimable_bytes"`
	BackupWarning            string `json:"backup_warning"`
}
type Coverage struct {
	Status       string `json:"status"`
	Visited      int    `json:"visited"`
	Inaccessible int    `json:"inaccessible"`
	Skipped      int    `json:"skipped"`
	BytesRead    int64  `json:"bytes_read"`
}
type Result struct {
	Feature          string    `json:"feature"`
	Support          string    `json:"support"`
	Coverage         Coverage  `json:"coverage"`
	Findings         []Finding `json:"findings"`
	Warnings         []string  `json:"warnings"`
	Errors           []string  `json:"errors"`
	Observations     []string  `json:"observations"`
	CollectionMethod string    `json:"collection_method"`
}
type Changes struct {
	FilesRemoved     int `json:"files_removed"`
	AppsUninstalled  int `json:"apps_uninstalled"`
	ProcessesStopped int `json:"processes_stopped"`
}
type Report struct {
	SchemaVersion    string      `json:"schema_version"`
	Product          string      `json:"product"`
	Version          string      `json:"version"`
	ScanID           string      `json:"scan_id"`
	Timestamp        time.Time   `json:"timestamp"`
	DisplayTimezone  string      `json:"display_timezone"`
	Environment      Environment `json:"environment"`
	Scope            Scope       `json:"scope"`
	SelectedFeatures []string    `json:"selected_features"`
	Method           string      `json:"method"`
	ElapsedSeconds   float64     `json:"elapsed_seconds"`
	Permissions      string      `json:"permissions"`
	AccuracyNotes    []string    `json:"accuracy_notes"`
	Results          []Result    `json:"results"`
	ActualChanges    Changes     `json:"actual_changes"`
}
