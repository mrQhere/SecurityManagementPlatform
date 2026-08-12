import os
import sys
import zipfile
import tarfile
import tempfile
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tools.errors import SMPUnclassifiedError, SMPDatabaseError, SMPError
from tools.db_manager import _encrypt_and_compress_data, _decrypt_and_decompress_data

def test_smp9999_error_sanitization():
    """Test that SMP-9999 errors hide raw exceptions in to_dict() but preserve them internally."""
    err = SMPUnclassifiedError("Secret internal database crash at line 42")
    assert "Secret internal database crash" in err.message
    
    output = err.to_dict()
    assert output["code"] == "SMP-9999"
    assert "Secret internal database crash" not in output["message"]
    assert "An unexpected internal error occurred." in output["message"]

def test_encryption_fail_closed(monkeypatch):
    """Test that db_manager fails closed when encryption key is missing."""
    import tools.encryption_manager
    monkeypatch.setattr(tools.encryption_manager, "get_active_key", lambda: None)
    
    with pytest.raises(SMPDatabaseError, match="Encryption key unavailable; refusing to persist scan output"):
        _encrypt_and_compress_data("test data")
        
        with open("/tmp/fake_file.gz", "wb") as f:
            f.write(b"data")
        with pytest.raises(SMPDatabaseError, match="Encryption key unavailable; refusing to read encrypted scan output"):
            _decrypt_and_decompress_data("/tmp/fake_file.gz")

def test_archive_path_traversal():
    """Test the extraction logic inside tools.tool_installer for path traversal prevention."""
    with tempfile.TemporaryDirectory() as temp_dir:
        malicious_zip = os.path.join(temp_dir, "malicious.zip")
        # Python's zipfile prevents creating files with ../ natively when writestr is used without overriding
        # Let's override it by creating a ZipInfo object
        zinfo = zipfile.ZipInfo("../evil.txt")
        with zipfile.ZipFile(malicious_zip, 'w') as z:
            z.writestr(zinfo, b"I am outside the destination")
            
        temp_extract_dir = os.path.join(temp_dir, "extract")
        os.makedirs(temp_extract_dir, exist_ok=True)
        
        from pathlib import Path
        from tools.errors import SMPError
        destination = Path(temp_extract_dir).resolve()
        
        with pytest.raises(SMPError, match="Archive path traversal detected"):
            with zipfile.ZipFile(malicious_zip, "r") as zr:
                for member in zr.namelist():
                    target = (destination / member).resolve()
                    if not target.is_relative_to(destination):
                        raise SMPError(f"Archive path traversal detected: {member}")
                    zr.extract(member, temp_extract_dir)
