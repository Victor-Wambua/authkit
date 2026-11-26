"""Breached-password checking: k-anonymity range model with an offline source."""

from __future__ import annotations

import secrets
import urllib.error
from pathlib import Path

import pytest

from authkit.app import SAMPLE_BREACH_FILE
from authkit.security.breach import (
    BreachCheckUnavailable,
    FailOpenChecker,
    HibpHttpSource,
    NullChecker,
    RangeBreachChecker,
    SortedHashFile,
    build_sorted_hash_file,
    sha1_hex,
)


@pytest.fixture
def hash_file(tmp_path: Path) -> tuple[Path, list[str]]:
    words = [f"leaked-{secrets.token_hex(4)}-{i}" for i in range(1500)]
    path = tmp_path / "hashes.txt"
    build_sorted_hash_file(words, path, count=7)
    return path, words


def test_sha1_matches_the_published_value_for_password() -> None:
    assert sha1_hex("password") == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"


def test_built_file_is_sorted_and_well_formed(hash_file: tuple[Path, list[str]]) -> None:
    lines = hash_file[0].read_text().splitlines()
    hashes = [ln.split(":")[0] for ln in lines]
    assert hashes == sorted(hashes)
    assert all(len(h) == 40 and ln.endswith(":7") for h, ln in zip(hashes, lines, strict=True))


def test_binary_search_finds_every_hash(hash_file: tuple[Path, list[str]]) -> None:
    path, words = hash_file
    checker = RangeBreachChecker(SortedHashFile(path))
    assert all(checker.pwned_count(w) == 7 for w in words)


def test_unknown_passwords_are_not_found(hash_file: tuple[Path, list[str]]) -> None:
    checker = RangeBreachChecker(SortedHashFile(hash_file[0]))
    assert checker.pwned_count("a passphrase nobody has leaked") == 0


def test_range_returns_only_suffixes_for_that_prefix(hash_file: tuple[Path, list[str]]) -> None:
    path, words = hash_file
    digest = sha1_hex(words[10])
    body = SortedHashFile(path).fetch(digest[:5])
    assert f"{digest[5:]}:7" in body.splitlines()
    assert all(len(line.split(":")[0]) == 35 for line in body.splitlines())


def test_missing_prefix_returns_empty(hash_file: tuple[Path, list[str]]) -> None:
    path, _ = hash_file
    present = {line[:5] for line in path.read_text().splitlines()}
    missing = next(f"{n:05X}" for n in range(0x100000) if f"{n:05X}" not in present)
    assert SortedHashFile(path).fetch(missing) == ""


def test_first_and_last_lines_are_reachable(hash_file: tuple[Path, list[str]]) -> None:
    path, _ = hash_file
    lines = path.read_text().splitlines()
    src = SortedHashFile(path)
    for line in (lines[0], lines[-1]):
        digest = line.split(":")[0]
        assert f"{digest[5:]}:7" in src.fetch(digest[:5]).splitlines()


def test_single_line_and_empty_files(tmp_path: Path) -> None:
    one = tmp_path / "one.txt"
    build_sorted_hash_file(["only-one-entry"], one)
    assert RangeBreachChecker(SortedHashFile(one)).pwned_count("only-one-entry") == 1
    assert RangeBreachChecker(SortedHashFile(one)).pwned_count("other") == 0
    empty = tmp_path / "empty.txt"
    empty.write_text("")
    assert RangeBreachChecker(SortedHashFile(empty)).pwned_count("x") == 0


def test_missing_file_raises_unavailable(tmp_path: Path) -> None:
    with pytest.raises(BreachCheckUnavailable):
        SortedHashFile(tmp_path / "nope.txt").fetch("ABCDE")


def test_only_the_five_character_prefix_leaves_the_checker() -> None:
    seen: list[str] = []

    class Spy:
        def fetch(self, prefix: str) -> str:
            seen.append(prefix)
            return ""

    RangeBreachChecker(Spy()).pwned_count("my very secret passphrase")
    digest = sha1_hex("my very secret passphrase")
    assert seen == [digest[:5]]
    assert digest[5:] not in seen[0]


def test_padding_entries_with_zero_count_are_ignored() -> None:
    digest = sha1_hex("padded-example")

    class Padded:
        def fetch(self, prefix: str) -> str:
            return f"{digest[5:]}:0\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:12"

    assert RangeBreachChecker(Padded()).pwned_count("padded-example") == 0


def test_shipped_sample_list_flags_common_passwords() -> None:
    checker = RangeBreachChecker(SortedHashFile(SAMPLE_BREACH_FILE))
    assert checker.pwned_count("password123") > 0
    assert checker.pwned_count("qwertyuiop123") > 0
    assert checker.pwned_count("correct horse battery staple") == 0


def test_null_checker_never_flags() -> None:
    assert NullChecker().pwned_count("password") == 0


def test_hibp_source_builds_the_range_url_and_never_needs_the_network() -> None:
    urls: list[str] = []

    def fake_fetch(url: str) -> str:
        urls.append(url)
        return "0018A45C4D1DEF81644B54AB7F969B88D65:3"

    src = HibpHttpSource(fetcher=fake_fetch)
    assert src.fetch("21bd1").startswith("0018A45")
    assert urls == ["https://api.pwnedpasswords.com/range/21BD1"]


def test_hibp_source_wraps_transport_errors() -> None:
    def boom(url: str) -> str:
        raise urllib.error.URLError("offline")

    with pytest.raises(BreachCheckUnavailable):
        HibpHttpSource(fetcher=boom).fetch("ABCDE")


def test_hibp_default_fetcher_refuses_non_https() -> None:
    with pytest.raises(BreachCheckUnavailable):
        HibpHttpSource()._http_get("http://insecure.example/range/ABCDE")


class _Down:
    def pwned_count(self, password: str) -> int:
        raise BreachCheckUnavailable("down")


def test_fail_open_allows_the_password_when_the_service_is_down() -> None:
    assert FailOpenChecker(_Down(), fail_open=True).pwned_count("x") == 0


def test_fail_closed_propagates_the_outage() -> None:
    with pytest.raises(BreachCheckUnavailable):
        FailOpenChecker(_Down(), fail_open=False).pwned_count("x")
