"""Tests for path resolution and file hashing."""

from pathlib import Path

import pytest

from virustotal_scan.file_utils import resolve_scan_paths, sha256_file


class TestResolveScanPaths:
    def test_single_file(self, tmp_path):
        file_path = tmp_path / "test.zip"
        file_path.write_text("content")
        files = resolve_scan_paths([str(file_path)])
        assert len(files) == 1
        assert files[0] == file_path

    def test_directory(self, tmp_path):
        (tmp_path / "a.zip").write_text("a")
        (tmp_path / "b.zip").write_text("b")
        files = resolve_scan_paths([str(tmp_path)])
        assert len(files) == 2

    def test_directory_sorted(self, tmp_path):
        (tmp_path / "b.zip").write_text("b")
        (tmp_path / "a.zip").write_text("a")
        files = resolve_scan_paths([str(tmp_path)])
        assert files[0].name == "a.zip"
        assert files[1].name == "b.zip"

    def test_missing_path_raises(self):
        with pytest.raises(SystemExit, match="FILE_ERROR"):
            resolve_scan_paths(["/nonexistent/file.zip"])

    def test_multiple_missing_paths_reported(self):
        with pytest.raises(SystemExit, match="not found: /a, /b"):
            resolve_scan_paths(["/a", "/b"])

    def test_multiple_paths_mix(self, tmp_path):
        dir_path = tmp_path / "d1"
        dir_path.mkdir()
        (dir_path / "a.zip").write_text("a")
        file_path = tmp_path / "single.zip"
        file_path.write_text("b")
        files = resolve_scan_paths([str(dir_path), str(file_path)])
        assert len(files) == 2

    def test_relative_path(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        file_path = Path("test.zip")
        file_path.write_text("content")
        files = resolve_scan_paths(["test.zip"])
        assert len(files) == 1
        assert files[0].name == "test.zip"

    def test_empty_paths_list(self):
        assert resolve_scan_paths([]) == []

    def test_skip_dirs_in_directory(self, tmp_path):
        (tmp_path / "file.zip").write_text("content")
        (tmp_path / "subdir").mkdir()
        files = resolve_scan_paths([str(tmp_path)])
        assert len(files) == 1
        assert files[0].name == "file.zip"


class TestSha256File:
    def test_known_hash(self, tmp_path):
        file_path = tmp_path / "test.bin"
        file_path.write_bytes(b"hello world")
        file_hash = sha256_file(file_path)
        assert file_hash == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

    def test_empty_file(self, tmp_path):
        file_path = tmp_path / "empty.bin"
        file_path.write_bytes(b"")
        file_hash = sha256_file(file_path)
        assert file_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
