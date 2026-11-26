import io
import zipfile

import pytest

from app.archive_utils import safe_extract_zip


def _archive(entries):
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        for name, content in entries:
            archive.writestr(name, content)
    payload.seek(0)
    return zipfile.ZipFile(payload)


def test_extracts_windows_style_member_paths(tmp_path):
    with _archive([("project\\frontend\\package.json", "{}")]) as archive:
        safe_extract_zip(archive, tmp_path)
    assert (tmp_path / "project" / "frontend" / "package.json").read_text() == "{}"


@pytest.mark.parametrize("name", ["../escape.txt", "folder\\..\\escape.txt", "/root.txt", "C:\\root.txt"])
def test_rejects_unsafe_member_paths(tmp_path, name):
    with _archive([(name, "unsafe")]) as archive:
        with pytest.raises(ValueError, match="不安全路径"):
            safe_extract_zip(archive, tmp_path)
