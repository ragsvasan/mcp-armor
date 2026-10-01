"""Identity-bearing key detection shared by ``_meta`` reconciliation
(middleware.request_meta) and baggage sanitization (telemetry.tracecontext).

A name-based safety net, not an authorization control: identity must come
only from the authenticated principal.
"""
from __future__ import annotations

import re
import unicodedata
from urllib.parse import unquote_plus


def _n(*names: str) -> frozenset[str]:
    return frozenset(_norm(n) for n in names)


def _norm(name: str) -> str:
    """NFKC + casefold, every non-alphanumeric removed: "Tenant-ID",
    "tenant:id", "ｔｅｎａｎｔ.id" → "tenantid"."""
    return re.sub(r"[\W_]", "", unicodedata.normalize("NFKC", name).casefold())


SUBJECT_NAMES = _n("user", "user_id", "uid", "sub", "subject", "principal", "on_behalf_of",
                    "act", "actor", "username", "email", "enduser", "enduser_id",
                    "impersonate", "impersonate_user", "run_as", "owner", "owner_id",
                    "identity", "caller", "customer_id", "oid", "upn", "login",
                    "preferred_username", "unique_name", "given_name", "family_name",
                    "nickname")
TENANT_NAMES = _n("tenant", "tenant_id", "org", "org_id", "organization", "organisation",
                   "account", "account_id", "workspace", "workspace_id", "project",
                   "project_id", "team", "team_id", "customer", "realm", "tid")
CLIENT_NAMES = _n("client_id", "azp", "appid", "cid")
SCOPE_NAMES = _n("role", "roles", "scope", "scopes", "scp", "permissions", "groups",
                  "entitlements", "authorities", "enduser_role", "enduser_scope", "wids",
                  "resource_access")
ADMIN_NAMES = _n("admin", "is_admin", "superuser", "root", "sudo", "elevated")
IDENTITY_NAMES = SUBJECT_NAMES | TENANT_NAMES | CLIENT_NAMES | SCOPE_NAMES | ADMIN_NAMES
# Word tokens that mark a key as identity-bearing even when its full name is
# not recognised ("acme/user_email", "actingAs", "delegatedUser"). Such keys
# cannot be compared to the principal, so they are rejected outright.
IDENTITY_TOKENS = frozenset({
    "tenant", "tenants", "org", "orgs", "organization", "organisation", "user", "users",
    "username", "subject", "sub", "principal", "role", "roles", "scope", "scopes", "admin",
    "email", "owner", "account", "actor", "acting", "impersonate", "impersonation",
    "delegate", "delegated", "delegation", "sudo", "uid", "enduser", "identity",
    "customer", "workspace", "permission", "permissions", "entitlement", "entitlements",
    "superuser", "realm", "team", "teams", "project", "projects", "group", "groups",
    "caller", "authorities", "authority", "elevated", "runas", "actas", "actingas",
    "azp", "scp", "tid", "oid", "upn", "wids", "appid", "cid", "idp", "sid", "nickname",
    # Token-envelope claims: cannot be reconciled against a principal.
    "iss", "aud",
})
# IDENTITY_NAMES words deliberately NOT treated as identity tokens (false
# positives outweigh value; the exact-name check still covers them):
#   "root" (rootDir, rootUri), "client" (clientVersion; client_id is exact-matched),
#   "act" (actions, active — "act" itself is exact-matched).
#   "login" (loginUrl; "login" itself is exact-matched).
TOKEN_EXEMPT_WORDS = frozenset({"root", "client", "act", "id", "login"})


_INVISIBLE_CATEGORIES = frozenset({"Cf", "Mn", "Me", "Cc"})


def _clean(key: str) -> str:
    """Matching form of a key: NFKD, drop invisible/combining characters (Cf
    zero-width/soft hyphen, Mn/Me combining marks and variation selectors,
    Cc controls) that would otherwise split or disguise an identity word,
    then NFKC. Used for matching only — callers log the original key."""
    return unicodedata.normalize("NFKC", "".join(
        c for c in unicodedata.normalize("NFKD", key)
        if unicodedata.category(c) not in _INVISIBLE_CATEGORIES))


def _views(key: str, prefixed: bool) -> list[str]:
    """Name strings to inspect for *key* (already cleaned).

    For a top-level ``_meta`` key (*prefixed*) the MCP prefix ends at the first
    '/': the name after it is inspected, plus the prefix labels joined to the
    name — dropping the first (reverse-DNS root) label of a multi-label prefix,
    so "org.example/feature" is not an org claim but "tenant/id",
    "acme.tenant/id" and "com.acme.user/id" are inspected as "tenant.id",
    "tenant.id" and "acme.user.id". Nested, baggage and tracestate keys have no
    prefix grammar: the whole key is the name.
    """
    if not prefixed or "/" not in key:
        return [key]
    prefix, name = key.split("/", 1)
    labels = [lbl for lbl in prefix.split(".") if lbl]
    kept = labels[1:] if len(labels) > 1 else labels
    return [name, ".".join([*kept, name])] if kept else [name]


def _tokens_of(name: str) -> set[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return {t for t in re.split(r"[\W_]+", spaced.casefold()) if t}


def name_tokens(key: str, *, prefixed: bool = True) -> set[str]:
    """Word tokens of every inspected name view (all segments)."""
    out: set[str] = set()
    for view in _views(_clean(key), prefixed):
        out |= _tokens_of(view)
    return out


def candidate_names(key: str, *, prefixed: bool = True) -> set[str]:
    """Normalized names a key could denote: each view whole, its last segment,
    and its last two segments joined, splitting on / . : @ =
    ("com.acme.tenant_id" → tenantid; "x/tenant/id" → tenantid;
    "tenant/id" → tenantid; "acme:tenant" → tenant)."""
    out: set[str] = set()
    for view in _views(_clean(key), prefixed):
        parts = [p for p in re.split(r"[/.:@=]", view) if p]
        out.add(_norm(view))
        if parts:
            out.add(_norm(parts[-1]))
            if len(parts) >= 2:
                out.add(_norm(parts[-2] + parts[-1]))
            if parts[-1][:2].lower() in ("x-", "x_"):     # "X-Tenant-ID" header style
                out.add(_norm(parts[-1][2:]))
    return out


_AFFIX_TOKENS = tuple(sorted(t for t in IDENTITY_TOKENS if len(t) >= 4))
_AFFIX_QUALIFIERS = frozenset({
    "id", "ids", "uid", "uuid", "guid", "name", "names", "role", "roles", "handle", "email",
    "mail", "slug", "key", "mode", "type", "info", "scope", "scopes", "level", "list",
    "ref", "code", "num", "number", "claim", "claims", "context", "ctx", "override",
})
_AFFIX_PREFIXES = frozenset({
    "is", "super", "end", "run", "runas", "act", "actas", "acting", "as", "my", "current",
    "effective", "delegated", "impersonated", "on", "for", "target", "real",
})


def has_identity_word(key: str, *, prefixed: bool = True) -> bool:
    """True if the key's name contains an identity word as a token, or — for
    unsegmented compounds ("userrole", "TENANTNAME", "issuperuser") — as the
    prefix or suffix of a token (identity words of 4+ letters only)."""
    toks = name_tokens(key, prefixed=prefixed)
    # Tokens plus whole segments ("onBehalfOf" camel-splits into on/behalf/of).
    segments = [seg for view in _views(_clean(key), prefixed)
                for seg in re.split(r"[/.:@=]", view)]
    norm_toks = {_norm(t) for t in toks} | {_norm(seg) for seg in segments}
    if toks & IDENTITY_TOKENS or (norm_toks & IDENTITY_NAMES) - TOKEN_EXEMPT_WORDS:
        return True
    # Compound forms only: identity word + known qualifier ("userrole",
    # "tenantname", "adminmode") or known prefix + identity word
    # ("issuperuser", "actasuser"). Plain substring affixes would flag
    # "factor"/"telescope"/"steam"/"grouping".
    for t in toks:
        for w in _AFFIX_TOKENS:
            if t.startswith(w) and t[len(w):] in _AFFIX_QUALIFIERS:
                return True
            if t.endswith(w) and t[:-len(w)] in _AFFIX_PREFIXES:
                return True
    return False


def is_identity_key(key: str, *, prefixed: bool = False) -> bool:
    """True if *key* names or contains an identity concept (percent/plus
    decoded first). *prefixed* applies the top-level ``_meta`` prefix
    grammar; baggage, tracestate and nested keys use the whole key."""
    decoded = unquote_plus(key)
    return bool(candidate_names(decoded, prefixed=prefixed) & IDENTITY_NAMES
                or has_identity_word(decoded, prefixed=prefixed))
