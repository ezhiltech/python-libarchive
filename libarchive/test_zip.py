import pytest
import os
import tempfile
from zip import sanitize_filename, ZipFile  # Import from zip.py

def test_sanitize_filename_safe():
    assert sanitize_filename("test.txt") == "test.txt"

def test_sanitize_filename_traversal():
    with pytest.raises(ValueError, match="Potential directory traversal attempt detected"):
        sanitize_filename("../etc/passwd")

def test_sanitize_filename_absolute_path():
    with pytest.raises(ValueError, match="Potential directory traversal attempt detected"):
        sanitize_filename("/etc/passwd")

def create_test_zip(zip_path, filenames):
    """Helper function to create a test ZIP file with given filenames."""
    import zipfile
    with zipfile.ZipFile(zip_path, 'w') as zf:
        for filename in filenames:
            zf.writestr(filename, "Test content")

def test_extract_safe():
    with tempfile.TemporaryDirectory() as temp_dir:
        zip_path = os.path.join(temp_dir, "test.zip")
        create_test_zip(zip_path, ["file1.txt", "subdir/file2.txt"])
       
        with ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extract("file1.txt", temp_dir)
       
        assert os.path.exists(os.path.join(temp_dir, "file1.txt"))

def test_extract_traversal_attack():
    with tempfile.TemporaryDirectory() as temp_dir:
        zip_path = os.path.join(temp_dir, "test.zip")
        create_test_zip(zip_path, ["../evil.txt"])

        with ZipFile(zip_path, 'r') as zip_ref:
            with pytest.raises(ValueError, match="Potential directory traversal attempt detected"):
                zip_ref.extract("../evil.txt", temp_dir)

def test_extractall_safe():
    with tempfile.TemporaryDirectory() as temp_dir:
        zip_path = os.path.join(temp_dir, "test.zip")
        create_test_zip(zip_path, ["file1.txt", "subdir/file2.txt"])
       
        with ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
       
        assert os.path.exists(os.path.join(temp_dir, "file1.txt"))
        assert os.path.exists(os.path.join(temp_dir, "subdir", "file2.txt"))

def test_extractall_with_traversal_attack():
    with tempfile.TemporaryDirectory() as temp_dir:
        zip_path = os.path.join(temp_dir, "test.zip")
        create_test_zip(zip_path, ["file1.txt", "../evil.txt"])

        with ZipFile(zip_path, 'r') as zip_ref:
            with pytest.raises(ValueError, match="Potential directory traversal attempt detected"):
                zip_ref.extractall(temp_dir)
