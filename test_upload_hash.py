
import io

from engines.hash_engine import (
    calculate_uploaded_file_hash,
    verify_uploaded_file
)

# Simulate an uploaded evidence file
sample_content = b"TRACE-X forensic evidence test"

uploaded_file = io.BytesIO(sample_content)
uploaded_file.name = "test_evidence.txt"

# Calculate SHA-256
original_hash = calculate_uploaded_file_hash(uploaded_file)

print("\n========== TRACE-X UPLOAD HASH TEST ==========")

print("File:", uploaded_file.name)
print("SHA-256:", original_hash)

# Verify unchanged evidence
result = verify_uploaded_file(uploaded_file, original_hash)

print("Integrity Status:", result["integrity_status"])

# Verify against an incorrect baseline
tampered_result = verify_uploaded_file(
    uploaded_file,
    "incorrect_hash"
)

print("Incorrect Baseline Test:", tampered_result["integrity_status"])

print("\n===============================================")
