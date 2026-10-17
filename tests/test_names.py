import pytest

from netwatch import names


@pytest.mark.parametrize("raw, clean", [
    ("living-room-tv.local.", "living-room-tv"),
    ("printer.lan", "printer"),
    ("192-168-50-20", None),
    ("192.168.50.20", None),
    ("", None),
    (None, None),
    ("nas", "nas"),
])
def test_clean(raw, clean):
    assert names.clean(raw) == clean
