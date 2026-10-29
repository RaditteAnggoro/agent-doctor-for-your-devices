# Agent Doctor For Your Devices — Review report

Scan: synthetic-scan-001 · Mode: READ-ONLY

All items are retained. Unknown values are shown as null. Local paths and application metadata are untrusted data.

## Scan metadata

    {
      "accuracy_notes": [
        "SYNTHETIC: not actual observations"
      ],
      "actual_changes": {
        "apps_uninstalled": 0,
        "files_removed": 0,
        "processes_stopped": 0
      },
      "display_timezone": "UTC",
      "elapsed_seconds": 0,
      "environment": {
        "architecture": "synthetic",
        "host_os": "synthetic",
        "limitations": null,
        "os": "synthetic",
        "os_version": "",
        "remote": false,
        "tools": null,
        "type": "fixture"
      },
      "method": "synthetic",
      "permissions": "No actual device access",
      "product": "Agent Doctor For Your Devices",
      "scan_id": "synthetic-scan-001",
      "schema_version": "1.0",
      "scope": {
        "exclusions": null,
        "max_bytes": 10000,
        "max_depth": 5,
        "max_files": 100,
        "roots": [
          "/synthetic"
        ]
      },
      "selected_features": [
        "junk",
        "performance",
        "applications",
        "duplicates"
      ],
      "timestamp": "2026-01-01T00:00:00Z",
      "version": "0.1.0"
    }

## junk

Support: SUPPORTED · Coverage: COMPLETED · Findings: 1

    {
      "collection_method": "synthetic metadata",
      "coverage": {
        "bytes_read": 0,
        "inaccessible": 0,
        "skipped": 0,
        "status": "COMPLETED",
        "visited": 0
      },
      "errors": null,
      "feature": "junk",
      "observations": null,
      "support": "SUPPORTED",
      "warnings": null
    }

### J-000001 — Synthetic temporary file for manual review

Risk: MODERATE · Confidence: MEDIUM · Decision guidance: INSPECT

    {
      "confidence": "MEDIUM",
      "evidence": [
        "Synthetic metadata"
      ],
      "feature": "junk",
      "id": "J-000001",
      "junk": {
        "active_use_hints": null,
        "backup": false,
        "basename": "file.tmp",
        "category": "temporary_file",
        "file": {
          "clone": null,
          "cloud": false,
          "device": "synthetic-device",
          "hardlink": null,
          "identity": "synthetic-id",
          "modified": "2026-01-01T00:00:00Z",
          "path": "/synthetic/資料/file.tmp",
          "size": 5,
          "sparse": null,
          "symlink": false
        },
        "kind": "file",
        "last_accessed": null,
        "owning_app": null,
        "reclaimable_bytes": null,
        "review_status": "REVIEW_WITH_CAUTION"
      },
      "limitations": [
        "Synthetic fixture only"
      ],
      "manual_inspection": "Review exact path manually",
      "paths": [
        "/synthetic/資料/file.tmp"
      ],
      "possible_consequences": "Loss of wanted data",
      "recommendation": "INSPECT",
      "risk": "MODERATE",
      "title": "Synthetic temporary file for manual review",
      "why_flagged": "Synthetic category and age"
    }

Candidate logical bytes: 5. Physical reclaimable space: UNKNOWN.

## performance

Support: SUPPORTED · Coverage: COMPLETED · Findings: 1

    {
      "collection_method": "synthetic metadata",
      "coverage": {
        "bytes_read": 0,
        "inaccessible": 0,
        "skipped": 0,
        "status": "COMPLETED",
        "visited": 0
      },
      "errors": null,
      "feature": "performance",
      "observations": null,
      "support": "SUPPORTED",
      "warnings": null
    }

### P-000001 — Synthetic observation

Risk: MODERATE · Confidence: MEDIUM · Decision guidance: INSPECT

    {
      "confidence": "MEDIUM",
      "evidence": [
        "Synthetic metadata"
      ],
      "feature": "performance",
      "id": "P-000001",
      "limitations": [
        "Synthetic fixture only"
      ],
      "manual_inspection": "Review exact path manually",
      "paths": [
        "/synthetic/資料/file.tmp"
      ],
      "performance": {
        "cpu_percent": null,
        "cpu_semantics": "Unavailable",
        "dependency_notes": "",
        "disk_available_bytes": null,
        "disk_total_bytes": null,
        "executable_path": null,
        "memory_available_bytes": null,
        "memory_total_bytes": null,
        "observation_seconds": 1,
        "observed_impact": "Unknown",
        "owner": null,
        "pid": null,
        "process_name": null,
        "rss_bytes": null,
        "running": null,
        "startup_source": null,
        "swap_used_bytes": null
      },
      "possible_consequences": "Loss of wanted data",
      "recommendation": "INSPECT",
      "risk": "MODERATE",
      "title": "Synthetic observation",
      "why_flagged": "Synthetic category and age"
    }

## applications

Support: SUPPORTED · Coverage: COMPLETED · Findings: 1

    {
      "collection_method": "synthetic metadata",
      "coverage": {
        "bytes_read": 0,
        "inaccessible": 0,
        "skipped": 0,
        "status": "COMPLETED",
        "visited": 0
      },
      "errors": null,
      "feature": "applications",
      "observations": null,
      "support": "SUPPORTED",
      "warnings": null
    }

### A-000001 — Synthetic application

Risk: MODERATE · Confidence: MEDIUM · Decision guidance: INSPECT

    {
      "application": {
        "dependency_notes": "",
        "install_size_bytes": null,
        "installed_at": null,
        "last_usage": null,
        "location": null,
        "name": "Synthetic App",
        "related_services": null,
        "running": null,
        "size_method": "",
        "source": "synthetic",
        "uninstall_method": "Use the OS interface",
        "updated_at": null,
        "usage_provenance": "UNKNOWN",
        "version": null
      },
      "confidence": "MEDIUM",
      "evidence": [
        "Synthetic metadata"
      ],
      "feature": "applications",
      "id": "A-000001",
      "limitations": [
        "Synthetic fixture only"
      ],
      "manual_inspection": "Review exact path manually",
      "paths": [
        "/synthetic/資料/file.tmp"
      ],
      "possible_consequences": "Loss of wanted data",
      "recommendation": "INSPECT",
      "risk": "MODERATE",
      "title": "Synthetic application",
      "why_flagged": "Synthetic category and age"
    }

## duplicates

Support: SUPPORTED · Coverage: COMPLETED · Findings: 1

    {
      "collection_method": "synthetic metadata",
      "coverage": {
        "bytes_read": 0,
        "inaccessible": 0,
        "skipped": 0,
        "status": "COMPLETED",
        "visited": 0
      },
      "errors": null,
      "feature": "duplicates",
      "observations": null,
      "support": "SUPPORTED",
      "warnings": null
    }

### D-000001 — Exact synthetic match

Risk: MODERATE · Confidence: MEDIUM · Decision guidance: INSPECT

    {
      "confidence": "MEDIUM",
      "duplicate": {
        "backup_warning": "Unknown",
        "digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "hash_algorithm": "SHA-256",
        "logical_redundant_bytes": 5,
        "match_type": "EXACT_CONTENT",
        "members": [
          {
            "clone": null,
            "cloud": false,
            "device": "synthetic-device",
            "hardlink": null,
            "identity": "synthetic-id",
            "modified": "2026-01-01T00:00:00Z",
            "path": "/synthetic/資料/file.tmp",
            "size": 5,
            "sparse": null,
            "symlink": false
          },
          {
            "clone": null,
            "cloud": false,
            "device": "synthetic-device",
            "hardlink": null,
            "identity": "second-id",
            "modified": "2026-01-01T00:00:00Z",
            "path": "/synthetic/copy.tmp",
            "size": 5,
            "sparse": null,
            "symlink": false
          }
        ],
        "physical_reclaimable_bytes": null,
        "retain_reason": "Neutral path ordering",
        "suggested_retain": "/synthetic/資料/file.tmp"
      },
      "evidence": [
        "Synthetic metadata"
      ],
      "feature": "duplicates",
      "id": "D-000001",
      "limitations": [
        "Synthetic fixture only"
      ],
      "manual_inspection": "Review exact path manually",
      "paths": [
        "/synthetic/資料/file.tmp"
      ],
      "possible_consequences": "Loss of wanted data",
      "recommendation": "INSPECT",
      "risk": "MODERATE",
      "title": "Exact synthetic match",
      "why_flagged": "Synthetic category and age"
    }

Logical redundant bytes: 5. Physical reclaimable space: UNKNOWN.

Changes: 0 files removed / 0 apps uninstalled / 0 processes stopped.
