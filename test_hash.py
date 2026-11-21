
from pathlib import Path
from engines.hash_engine import calculate_sha256, verify_file_integrity

evidence_file = Path("evidence/sample_evidence.txt")
baseline_file = Path("evidence/sample_evidence.sha256")

# Create sample evidence if it doesn't exist
if not evidence_file.exists():
    evidence_file.write_text(
        "TRACE-X Digital Forensic Evidence",
        encoding="utf-8"
    )

# Preserve the original hash only once
if not baseline_file.exists():
    original_hash = calculate_sha256(evidence_file)
    baseline_file.write_text(original_hash, encoding="utf-8")
    print("Original evidence fingerprint saved!")

# Read the preserved baseline
original_hash = baseline_file.read_text(encoding="utf-8").strip()

# Verify current evidence against original fingerprint
result = verify_file_integrity(evidence_file, original_hash)

print("\n========== TRACE-X INTEGRITY REPORT ==========")
print("Evidence file:", result["file"])
print("Original hash:", result["original_hash"])
print("Current hash: ", result["current_hash"])
print("Integrity status:", result["integrity_status"])
print("==============================================")
