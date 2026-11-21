
import hashlib
from pathlib import Path


def calculate_sha256(file_path):
    """
    Calculate the SHA-256 hash of a file.
    """

    sha256_hash = hashlib.sha256()

    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    if not file_path.is_file():
        raise ValueError(f"Not a valid file: {file_path}")

    with file_path.open("rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256_hash.update(chunk)

    return sha256_hash.hexdigest()


def verify_file_integrity(file_path, original_hash):
    """
    Compare the current file hash with the original hash.
    """

    current_hash = calculate_sha256(file_path)

    return {
        "file": Path(file_path).name,
        "original_hash": original_hash,
        "current_hash": current_hash,
        "integrity_status": (
            "MATCH" if current_hash == original_hash
            else "MISMATCH"
        )
    }

import hashlib


def calculate_uploaded_file_hash(uploaded_file):
    """
    Calculate SHA-256 hash directly from an uploaded file.
    Does not modify the original file.
    """

    file_bytes = uploaded_file.getvalue()

    sha256_hash = hashlib.sha256(file_bytes).hexdigest()

    return sha256_hash


def verify_uploaded_file(uploaded_file, original_hash):
    """
    Compare uploaded evidence against its original SHA-256 hash.
    """

    current_hash = calculate_uploaded_file_hash(uploaded_file)

    return {
        "file": uploaded_file.name,
        "original_hash": original_hash,
        "current_hash": current_hash,
        "integrity_status": (
            "MATCH"
            if current_hash.lower() == original_hash.strip().lower()
            else "MISMATCH"
        )
    }
