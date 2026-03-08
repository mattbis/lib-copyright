# lib-copyright/timestamp.py
"""
OpenTimestamps integration for proof-of-existence / poor man's copyright.

Not tested yet... just more brain storming....
"""

import os
from opentimestamps.client.stamp import DetachedTimestampFile, Calendar
from opentimestamps.client.op import OpSHA256, OpPrepend
from opentimestamps.client.util import hash_sha256d

def timestamp_file(file_path: str, calendar_urls=None) -> str:
    """
    Timestamp a file using OpenTimestamps and return path to .ots proof file.
    
    Args:
        file_path: Path to the file to timestamp (e.g. audio master WAV)
        calendar_urls: Optional list of calendar servers (default public ones)
    
    Returns:
        Path to the generated .ots proof file
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    # Default public calendars (free, reliable in 2026)
    if calendar_urls is None:
        calendar_urls = [
            "https://a.pool.opentimestamps.org",
            "https://b.pool.opentimestamps.org",
            "https://finney.calendar.eternitywall.com",
        ]

    # Read file bytes
    with open(file_path, "rb") as f:
        file_bytes = f.read()

    # Create detached timestamp (hash + nonce for privacy)
    # Simple version: just SHA256
    digest = hash_sha256d(file_bytes)  # or use OpSHA256 directly

    # Build the initial commitment
    commitment = DetachedTimestampFile.from_digest(OpSHA256(digest))

    # Submit to calendars (this contacts them and builds the proof path)
    for url in calendar_urls:
        calendar = Calendar(url)
        try:
            calendar.submit(commitment)
            print(f"Submitted to {url}")
        except Exception as e:
            print(f"Calendar {url} failed: {e}")

    # Upgrade to Bitcoin level (wait for aggregation & Bitcoin tx)
    # Note: This may need to be run later if aggregation is incomplete
    from opentimestamps.client.stamp import upgrade_timestamp
    upgraded = upgrade_timestamp(commitment)

    # Save the proof
    ots_path = file_path + ".ots"
    with open(ots_path, "wb") as f:
        f.write(upgraded.serialize())

    print(f"Proof saved: {ots_path}")
    return ots_path


def verify_timestamp(ots_path: str, original_file_path: str = None) -> bool:
    """
    Verify a .ots proof against the original file (or just check proof validity).
    """
    from opentimestamps.client.verify import verify_timestamp_file

    if original_file_path:
        with open(original_file_path, "rb") as f:
            file_bytes = f.read()
        digest = hash_sha256d(file_bytes)
        commitment = DetachedTimestampFile.from_digest(OpSHA256(digest))
    else:
        commitment = None  # Verify proof standalone

    try:
        result = verify_timestamp_file(ots_path, commitment)
        print(f"Verification result: {result}")
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False


# Example usage
if __name__ == "__main__":
    proof_file = timestamp_file("path/to/your_final_track.wav")
    # Later...
    verify_timestamp(proof_file, "path/to/your_final_track.wav")
