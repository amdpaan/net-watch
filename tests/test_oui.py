import pytest

from conftest import FIXTURES
from netwatch import oui


@pytest.fixture(autouse=True)
def table():
    oui.load(FIXTURES / "manuf_sample.txt")
    yield
    oui._table = None


@pytest.mark.parametrize("mac, vendor", [
    ("00:00:5e:00:40:01", "Example Thirty-Six Bit"),   # /36 beats /24
    ("00:00:5e:12:34:56", "Example Twenty-Eight"),     # /28 beats /24
    ("00:00:5e:00:53:01", "ICANN, IANA Department"),   # plain /24
    ("70:b3:d5:12:30:aa", "Tiny Sensor"),
    ("70:b3:d5:99:00:00", "IEEE Registration Authority"),
    ("10:20:30:aa:bb:cc", "Fruitco"),
    ("40:50:60:00:00:01", "Telly Electronics"),
    ("00:00:5f:00:00:01", None),
])
def test_vendor(mac, vendor):
    assert oui.vendor(mac) == vendor


def test_private_mac_never_looked_up():
    assert oui.vendor("a2:11:22:33:44:55") == oui.PRIVATE
    assert oui.vendor("12:20:30:aa:bb:cc") == oui.PRIVATE  # 0x12 has the local bit, despite matching 10:20:30


def test_missing_cache_means_unknown(data_home):
    oui._table = None
    assert oui.vendor("10:20:30:aa:bb:cc") is None


def test_download_rejects_garbage(monkeypatch, tmp_path):
    page = tmp_path / "page.html"
    page.write_text("<html>Not found</html>")
    with pytest.raises(ValueError):
        oui.download(page.as_uri())
    assert not oui.have_cache()


def test_download_saves_cache(tmp_path):
    big = tmp_path / "manuf"
    big.write_text("".join("%06X\tV%d\tVendor %d\n" % (i, i, i) for i in range(1500)))
    assert oui.download(big.as_uri()) == 1500
    assert oui.have_cache()
    assert oui.vendor("00:00:05:00:00:00") == "Vendor 5"
