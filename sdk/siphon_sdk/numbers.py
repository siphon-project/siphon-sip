"""Mock ``numbers`` namespace — E.164 identity normalization.

Mirrors the Rust ``PyNumbersNamespace`` / ``PyNumber`` and the identity walk
behind ``request.rewrite_identities()`` / ``call.rewrite_identities()`` /
``call.dial(number_policy=…)``. The parse/format logic here reproduces
``src/numbers/mod.rs`` so pytest-based script tests exercise the real behaviour.

Usage::

    from siphon import numbers

    n = numbers.parse("0031612345678")
    n.e164        # "+31612345678"
    n.national    # "0612345678"
    n.format("plain")

Tests configure the home numbering plan and named policies via the harness::

    from siphon_sdk import mock_module
    mock_module.get_numbers().configure(country_code="31")
    mock_module.get_numbers().register_policy("teams-outbound@2026", default="e164")
"""

from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional


_FORMATS = ("e164", "plain", "international", "national")

# Header token -> canonical identity header name (matches IdentityHeader).
_IDENTITY_TOKENS = {
    "request-uri": "request-uri",
    "ruri": "request-uri",
    "r-uri": "request-uri",
    "uri": "request-uri",
    "to": "To",
    "from": "From",
    "p-asserted-identity": "P-Asserted-Identity",
    "pai": "P-Asserted-Identity",
    "p-preferred-identity": "P-Preferred-Identity",
    "ppi": "P-Preferred-Identity",
    "referred-by": "Referred-By",
    "remote-party-id": "Remote-Party-ID",
    "rpid": "Remote-Party-ID",
}

_DEFAULT_HEADERS = ["From", "To", "P-Asserted-Identity", "P-Preferred-Identity", "request-uri"]


class Locale:
    """Home numbering plan (country code + trunk/international prefixes)."""

    def __init__(
        self,
        country_code: str = "",
        trunk_prefix: str = "0",
        international_prefix: str = "00",
        assume: str = "national",
        min_national_digits: int = 5,
    ) -> None:
        self.country_code = country_code.lstrip("+").strip()
        self.trunk_prefix = trunk_prefix
        self.international_prefix = international_prefix
        self.assume = assume
        self.min_national_digits = min_national_digits


class Number:
    """A parsed telephone number — format it into any E.164 shape."""

    def __init__(self, international: str, locale: Locale) -> None:
        self._international = international
        self._locale = locale
        cc = locale.country_code
        self._cc = cc if cc and international.startswith(cc) else None

    @property
    def e164(self) -> str:
        """Global E.164 with a leading ``+`` (e.g. ``+31612345678``)."""
        return "+" + self._international

    @property
    def plain(self) -> str:
        """E.164 digits, no ``+`` (e.g. ``31612345678``)."""
        return self._international

    @property
    def international(self) -> str:
        """International access form (e.g. ``0031612345678``)."""
        return self._locale.international_prefix + self._international

    @property
    def national(self) -> str:
        """National trunk form (e.g. ``0612345678``); international form for a
        foreign number."""
        if self._cc is not None:
            nsn = self._international[len(self._cc):]
            return self._locale.trunk_prefix + nsn
        return self._locale.international_prefix + self._international

    @property
    def cc(self) -> Optional[str]:
        """Country code, if it matched the configured home country."""
        return self._cc

    @property
    def nsn(self) -> str:
        """National significant number (digits after the country code)."""
        if self._cc is not None:
            return self._international[len(self._cc):]
        return self._international

    def format(self, fmt: str) -> str:
        """Format into ``"e164"`` | ``"plain"`` | ``"international"`` |
        ``"national"``."""
        fmt = fmt.strip().lower()
        if fmt not in _FORMATS:
            raise ValueError(f"unknown number format {fmt!r}")
        return getattr(self, fmt)

    def __str__(self) -> str:
        return self.e164

    def __repr__(self) -> str:
        return f"<Number {self.e164}>"


def _parse(raw: str, locale: Locale) -> Optional[Number]:
    """Parse a userpart into a :class:`Number`, or ``None`` when it is not a
    dialable number (the walk's skip signal)."""
    raw = raw.strip()
    if not raw:
        return None

    had_plus = False
    digits = []
    for index, ch in enumerate(raw):
        if ch == "+" and index == 0:
            had_plus = True
        elif ch.isdigit():
            digits.append(ch)
        elif ch in "-.() ":
            continue
        else:
            return None
    if not digits:
        return None
    cleaned = "".join(digits)

    intl = locale.international_prefix
    trunk = locale.trunk_prefix
    if had_plus:
        international, national_form = cleaned, False
    elif intl and cleaned.startswith(intl):
        international, national_form = cleaned[len(intl):], False
    elif trunk and cleaned.startswith(trunk):
        international, national_form = locale.country_code + cleaned[len(trunk):], True
    elif locale.assume == "international":
        international, national_form = cleaned, True
    else:
        international, national_form = locale.country_code + cleaned, True

    if not international or len(international) > 15:
        return None
    if national_form:
        significant = len(international) - len(locale.country_code)
        if significant < locale.min_national_digits:
            return None
    return Number(international, locale)


def _glob_match(pattern: str, subject: str) -> bool:
    if pattern == "*":
        return True
    if pattern.endswith("*"):
        return subject.startswith(pattern[:-1])
    if pattern.startswith("*"):
        return subject.endswith(pattern[1:])
    return pattern == subject


class _Policy:
    def __init__(
        self,
        locale: Locale,
        default_format: str,
        header_formats: Dict[str, str],
        headers: List[str],
        on_unparseable: str,
        preserve_users: List[str],
    ) -> None:
        self.locale = locale
        self.default_format = default_format
        self.header_formats = header_formats
        self.headers = headers
        self.on_unparseable = on_unparseable
        self.preserve_users = preserve_users

    def format_for(self, header: str) -> str:
        return self.header_formats.get(header, self.default_format)

    def reformat_user(self, user: str, target: str) -> Optional[str]:
        """Return the reformatted userpart, or ``None`` to leave it unchanged."""
        if not user or any(_glob_match(p, user) for p in self.preserve_users):
            return None
        number = _parse(user, self.locale)
        if number is None:
            return None
        return number.format(target)


_SIP_USER_RE = re.compile(r"(sips?:)([^@>\s;]+)(@)")
_TEL_USER_RE = re.compile(r"(tel:)([^>\s;]+)")


def rewrite_nameaddr_userpart(value: str, reformat: Callable[[str], Optional[str]]) -> str:
    """Reformat the userpart inside a name-addr header value (``"Alice"
    <sip:0612…@host>;tag=…`` or ``<tel:0612…>``), preserving display name,
    tag, host and params. ``reformat`` returns the new userpart or ``None`` to
    leave it unchanged."""

    def sub_sip(match: "re.Match[str]") -> str:
        new = reformat(match.group(2))
        return match.group(1) + (new if new is not None else match.group(2)) + match.group(3)

    def sub_tel(match: "re.Match[str]") -> str:
        new = reformat(match.group(2))
        return match.group(1) + (new if new is not None else match.group(2))

    if _SIP_USER_RE.search(value):
        return _SIP_USER_RE.sub(sub_sip, value, count=1)
    if _TEL_USER_RE.search(value):
        return _TEL_USER_RE.sub(sub_tel, value, count=1)
    return value


class MockNumbersNamespace:
    """Mock ``numbers`` namespace (mirrors the Rust ``NumbersNamespace``)."""

    def __init__(self) -> None:
        self._locale = Locale()
        self._policies: Dict[str, dict] = {}
        self._default_b2bua_policy: Optional[str] = None

    # -- test harness helpers (not part of the runtime API) -----------------

    def configure(self, default_number_policy: Optional[str] = None, **kwargs) -> None:
        """Set the home numbering plan for tests (country_code, trunk_prefix,
        international_prefix, assume, min_national_digits), and optionally the
        B2BUA default policy (``default_number_policy``)."""
        if default_number_policy is not None:
            self._default_b2bua_policy = default_number_policy
        if kwargs:
            self._locale = Locale(**{**self._locale_kwargs(), **kwargs})

    def register_policy(self, name: str, **spec) -> None:
        """Register a named policy for tests. Accepts default, headers (dict),
        walk (list), on_unparseable, preserve_users, country_code."""
        self._policies[name] = spec

    def clear(self) -> None:
        self._locale = Locale()
        self._policies.clear()
        self._default_b2bua_policy = None

    def _locale_kwargs(self) -> dict:
        loc = self._locale
        return {
            "country_code": loc.country_code,
            "trunk_prefix": loc.trunk_prefix,
            "international_prefix": loc.international_prefix,
            "assume": loc.assume,
            "min_national_digits": loc.min_national_digits,
        }

    # -- runtime API --------------------------------------------------------

    def parse(self, raw: str, home: Optional[str] = None) -> Number:
        """Parse a raw number string into a :class:`Number`.

        Raises ``ValueError`` when the string is not a dialable number.
        """
        locale = self._locale
        if home is not None:
            locale = Locale(**{**self._locale_kwargs(), "country_code": home})
        number = _parse(raw, locale)
        if number is None:
            raise ValueError(f"not a dialable number: {raw!r}")
        return number

    def policy_names(self) -> List[str]:
        """Names of the configured number policies."""
        return sorted(self._policies)

    # -- internal: resolve an inline/named policy for rewrite_identities ----

    def _resolve(
        self,
        policy: Optional[str],
        format: Optional[str],
        headers: Optional[List[str]],
        home: Optional[str],
    ) -> _Policy:
        if policy is not None:
            if format is not None or headers is not None:
                raise ValueError("rewrite_identities(): pass either policy= or format=, not both")
            spec = self._policies.get(policy)
            if spec is None:
                raise ValueError(f"unknown number policy {policy!r}")
            return self._policy_from_spec(spec)

        if format is None:
            raise ValueError("rewrite_identities(): requires policy= (named) or format= (inline)")
        fmt = format.strip().lower()
        if fmt not in _FORMATS:
            raise ValueError(f"unknown number format {format!r}")

        walk: List[str] = []
        for token in headers if headers is not None else _DEFAULT_HEADERS:
            canonical = _IDENTITY_TOKENS.get(token.strip().lower())
            if canonical is None:
                raise ValueError(f"unknown identity header {token!r}")
            if canonical not in walk:
                walk.append(canonical)

        locale = self._locale
        if home is not None:
            locale = Locale(**{**self._locale_kwargs(), "country_code": home})
        return _Policy(locale, fmt, {}, walk, "keep", [])

    def _resolve_dial(self, name: Optional[str]) -> Optional[_Policy]:
        """Resolve the B2BUA dial/fork policy: explicit name, else the
        configured default, else ``None`` (no normalization)."""
        resolved_name = name or self._default_b2bua_policy
        if resolved_name is None:
            return None
        spec = self._policies.get(resolved_name)
        if spec is None:
            raise ValueError(f"unknown number policy {resolved_name!r}")
        return self._policy_from_spec(spec)

    def _policy_from_spec(self, spec: dict) -> _Policy:
        header_formats: Dict[str, str] = {}
        for token, fmt in (spec.get("headers") or {}).items():
            canonical = _IDENTITY_TOKENS.get(token.strip().lower())
            if canonical is not None:
                header_formats[canonical] = fmt
        walk_tokens = spec.get("walk")
        walk = []
        for token in walk_tokens if walk_tokens is not None else _DEFAULT_HEADERS:
            canonical = _IDENTITY_TOKENS.get(token.strip().lower())
            if canonical is not None and canonical not in walk:
                walk.append(canonical)
        for header in header_formats:
            if header not in walk:
                walk.append(header)
        cc = spec.get("country_code", self._locale.country_code)
        locale = Locale(**{**self._locale_kwargs(), "country_code": cc})
        return _Policy(
            locale,
            spec.get("default", "e164"),
            header_formats,
            walk,
            spec.get("on_unparseable", "keep"),
            spec.get("preserve_users", []) or [],
        )
