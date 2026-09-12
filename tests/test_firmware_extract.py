"""Tests for the recursive extraction engine and its guards."""

import gzip
import io
import json
import os
import tarfile

from iiatool.firmware import extract


def _tar_with_gzip(tmp_path) -> str:
    """
    Write a tar containing a nested gzip stream.

    Parameters
    ----------
    tmp_path : pathlib.Path
        Temporary directory.

    Returns
    -------
    str
        Tar file path.
    """
    inner = gzip.compress(b"deep payload")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as archive:
        info = tarfile.TarInfo("nested.gz")
        info.size = len(inner)
        archive.addfile(info, io.BytesIO(inner))
    path = tmp_path / "fw.tar"
    path.write_bytes(buf.getvalue())
    return str(path)


class TestExtract:
    def test_recurses_into_nested_gzip(self, tmp_path):
        target = _tar_with_gzip(tmp_path)
        out = tmp_path / "out"
        result = extract.extract_tree(target, str(out))
        assert result["files"] >= 2
        assert os.path.exists(os.path.join(str(out), "manifest.json"))

    def test_directory_input(self, tmp_path):
        (tmp_path / "a.gz").write_bytes(gzip.compress(b"x"))
        out = tmp_path / "out"
        result = extract.extract_tree(str(tmp_path), str(out))
        assert result["files"] >= 1

    def test_identify_and_extract_alias(self, tmp_path):
        target = tmp_path / "a.gz"
        target.write_bytes(gzip.compress(b"x"))
        result = extract.identify_and_extract(str(target), str(tmp_path / "o"))
        assert result["source"].endswith("a.gz")

    def test_manifest_contents(self, tmp_path):
        target = _tar_with_gzip(tmp_path)
        out = tmp_path / "out"
        extract.extract_tree(target, str(out))
        with open(os.path.join(str(out), "manifest.json")) as handle:
            doc = json.load(handle)
        assert doc["files"] >= 2

    def test_stream_handler(self, tmp_path):
        handler = extract._stream("gzip")
        entries = handler(gzip.compress(b"hello"), str(tmp_path), 1024)
        assert entries[0]["size"] == 5

    def test_stream_unsupported(self, tmp_path):
        handler = extract._stream("gzip")
        assert handler(b"not-gzip", str(tmp_path), 1024) == []

    def test_extractable_none(self):
        assert (
            extract._extractable(
                [{"type": "unknown", "offset": 0, "confidence": 1}]
            )
            is None
        )

    def test_extractable_skips_unregistered(self):
        findings = [
            {"type": "unknown", "offset": 0, "confidence": 1},
            {"type": "gzip", "offset": 8, "confidence": 1},
        ]
        assert extract._extractable(findings)["type"] == "gzip"

    def test_run_without_handler(self, tmp_path):
        state = {"depth": 1, "files": 0, "bytes": 0}
        assert extract._run({"type": "nope"}, b"x", str(tmp_path), state) == []

    def test_read_missing(self):
        assert extract._read("/nonexistent/path") == b""

    def test_recurse_depth_zero(self, tmp_path):
        state = {"depth": 0, "files": 0, "bytes": 0}
        assert extract._recurse("/anything", str(tmp_path), state) == []

    def test_descend_counts(self, tmp_path):
        state = {"depth": 1, "files": 0, "bytes": 0}
        written = [{"path": "/nonexistent", "size": 10, "member": "x"}]
        manifest = extract._descend(written, str(tmp_path), state)
        assert state["files"] == 1
        assert state["bytes"] == 10
        assert manifest[0]["size"] == 10

    def test_guard_max_files(self, tmp_path):
        target = _tar_with_gzip(tmp_path)
        state = {"depth": 8, "files": extract.MAX_FILES, "bytes": 0}
        assert extract._recurse(target, str(tmp_path), state) == []

    def test_registry_complete(self):
        for name in (
            "gzip",
            "xz",
            "zstd",
            "tar",
            "zip",
            "cpio",
            "squashfs-le",
        ):
            assert name in extract.REGISTRY
