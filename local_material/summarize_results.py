"""Validate local accounting and record source provenance; no secret logging."""
import datetime
import hashlib
import json
import pathlib
import platform
import statistics
import subprocess

root = pathlib.Path(__file__).resolve().parent.parent
results = root / "local_material" / "results"
reports = {}
for name in ("functional", "8mb"):
    report = json.loads((results / f"{name}.json").read_text())
    assert report["backend"] == "local-simulation-NOT-TEE"
    assert report["hardware_attested"] is False
    assert report["attestation_and_private_channel_bytes"] is None
    count = report["queries_correct"]
    assert report["online_rlwe_component_payload_bytes"] == count * report["static_rlwe_component_payload_bytes"]
    assert len(report["online_with_local_ipc_ms"]) == count
    assert len(report["server_with_local_ipc_ms"]) == count
    assert len(report["server_compute_ms"]) == count
    expected = sum(report[key] for key in (
        "public_setup_payload_bytes", "seed_provisioning_payload_bytes",
        "readiness_receipts_payload_bytes", "online_query_payload_bytes",
        "online_response_payload_bytes", "release_control_payload_bytes"))
    assert expected == report["logical_client_payload_total_bytes"]
    mean_online_ms = statistics.mean(report["online_with_local_ipc_ms"])
    mean_server_ms = statistics.mean(report["server_with_local_ipc_ms"])
    mean_server_compute_ms = statistics.mean(report["server_compute_ms"])
    database_mib = report["database_bytes"] / (1024 * 1024)
    reports[name] = {
        "correct_queries": count,
        "mean_local_online_ms": mean_online_ms,
        "mean_server_with_local_ipc_ms": mean_server_ms,
        "mean_server_compute_ms": mean_server_compute_ms,
        "end_to_end_queries_per_second": 1000 / mean_online_ms,
        "server_queries_per_second": 1000 / mean_server_ms,
        "server_compute_queries_per_second": 1000 / mean_server_compute_ms,
        "end_to_end_database_throughput_mib_s": database_mib * 1000 / mean_online_ms,
        "server_database_throughput_mib_s": database_mib * 1000 / mean_server_ms,
        "server_compute_database_throughput_mib_s": database_mib * 1000 / mean_server_compute_ms,
        "mean_preparation_ms": statistics.mean(report["prepare_with_local_ipc_ms"]),
        "online_query_bytes_per_query": report["online_query_payload_bytes"] / count,
        "client_total_payload_bytes": expected,
        "static_half_matches_online_rlwe_half": True,
    }

fingerprint = hashlib.sha256()
for folder in ("local_material", "hintless_simplepir", "linpir", "lwe"):
    for path in sorted((root / folder).iterdir()):
        if path.is_file() and (path.suffix in (".h", ".cc", ".proto", ".sh", ".py") or path.name == "BUILD"):
            fingerprint.update(str(path.relative_to(root)).encode())
            fingerprint.update(path.read_bytes())
fingerprint.update((root / ".bazelrc").read_bytes())
manifest = {
    "recorded_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "kernel": platform.platform(),
    "base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
    "branch": subprocess.check_output(["git", "branch", "--show-current"], cwd=root, text=True).strip(),
    "source_sha256_at_recording": fingerprint.hexdigest(),
    "build": "Bazel -c opt, C++17, local WSL/Linux",
    "scope": "Correctness and application payload accounting only; no hardware TEE, secure erasure, concrete security estimate, network throughput or stable latency claim.",
    "profiles": reports,
}
(results / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(json.dumps(manifest, indent=2))
