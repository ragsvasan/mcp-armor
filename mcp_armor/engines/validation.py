"""T3 — Input Validation: JSON schema strict mode, injection guards, size limits."""

from __future__ import annotations

from ..context import CoSAIContext
from ..exceptions import ValidationError
from ..types import (
    CONTENT_BEARING_METHODS,
    MCPRequest,
    MCPResponse,
    scannable_strings,
)

_MAX_PAYLOAD_BYTES = 65_536

# T3-002: shell command injection
_CMD_PATTERNS: tuple[str, ...] = (
    r"[;&|`]",
    r"\$\(",
    r"\$\{",                           # ${VAR} and ${IFS} expansions
    r"[<>]",                           # shell redirects
    r"(?i)\bexec\s*\(",
    r"(?i)\beval\s*\(",
    r"(?i)\bsystem\s*\(",
    r"(?i)\bpopen\s*\(",
    r"(?i)\bcmd\s*/[cCkK]\b",         # Windows cmd /c
    r"(?i)%[A-Za-z_][A-Za-z_0-9]*%", # Windows %ENVVAR%
)

# T3-003: path traversal
_PATH_PATTERNS: tuple[str, ...] = (
    r"\.\.[/\\]",
    r"[/\\]\.\.",
    r"(?i)%2e%2e(?:[/\\]|%2f|%5c)",
    r"(?i)%252e%252e",
    r"(?i)/etc/",
    r"(?i)/proc/self",
    r"(?i)(?:/root|/home/[^/]+)/\.ssh/",
    r"(?i)[A-Za-z]:[/\\](?:Windows|System32|Users)",
    r"(?i)\\\\\.\\\\",
)

# T3-004: SQL injection
_SQL_PATTERNS: tuple[str, ...] = (
    r"(?i)'\s*(OR|AND)\s+['\"0-9]",
    r"(?i)\b(OR|AND)\s+\d+\s*=\s*\d+",  # numeric tautology: OR 1=1
    r"(?i);\s*(?:DROP|DELETE|TRUNCATE|INSERT|UPDATE|ALTER|CREATE)\s+",
    r"(?i)UNION\s+(?:ALL\s+)?SELECT",
    r"--",                              # SQL comment (all forms)
    r"(?i)/\*.*?\*/",
    r"(?i)\bXP_\w+",
    r"(?i)WAITFOR\s+DELAY",
    r"(?i)SLEEP\s*\(",
)


def _compile(patterns: tuple[str, ...]) -> list:
    try:
        import re2 as re
    except ImportError:
        import re  # type: ignore[no-redef]
    return [re.compile(p) for p in patterns]


class ValidationEngine:
    """
    Validates all tool call inputs before dispatch.

    Covers:
    - T3-001: Oversized payload (denial of service via memory exhaustion)
    - T3-002: Command injection in string arguments (including nested containers)
    - T3-003: Path traversal (../ sequences)
    - T3-004: SQL injection patterns
    - T3-005: Unknown fields in strict-schema mode / required fields missing
    """

    def __init__(
        self,
        max_payload_bytes: int = _MAX_PAYLOAD_BYTES,
        strict_schema: bool = True,
    ) -> None:
        self._max_payload_bytes = max_payload_bytes
        self._strict_schema = strict_schema
        self._tool_schemas: dict[str, dict] = {}
        self._cmd = _compile(_CMD_PATTERNS)
        self._path = _compile(_PATH_PATTERNS)
        self._sql = _compile(_SQL_PATTERNS)

    def register_tools(self, tools: list[dict]) -> None:
        """Populate tool input schemas from a tools/list result. Called by CoSAIGuard."""
        for tool in tools:
            name = tool.get("name", "")
            schema = tool.get("inputSchema") or {}
            if name:
                self._tool_schemas[name] = schema

    def _scan_injection(self, value: str, field: str) -> None:
        for pat in self._cmd:
            if pat.search(value):
                raise ValidationError(
                    f"Command injection pattern in argument {field!r}: {pat.pattern!r}"
                )
        for pat in self._path:
            if pat.search(value):
                raise ValidationError(
                    f"Path traversal pattern in argument {field!r}: {pat.pattern!r}"
                )
        for pat in self._sql:
            if pat.search(value):
                raise ValidationError(
                    f"SQL injection pattern in argument {field!r}: {pat.pattern!r}"
                )

    def _scan_all_strings(self, value: object, field: str) -> None:
        """Recursively scan all string values inside dicts and lists."""
        if isinstance(value, str):
            self._scan_injection(value, field)
        elif isinstance(value, list):
            for i, item in enumerate(value):
                self._scan_all_strings(item, f"{field}[{i}]")
        elif isinstance(value, dict):
            for k, v in value.items():
                self._scan_all_strings(v, f"{field}.{k}")

    def _validate_schema(self, arguments: object, schema: dict, tool_name: str) -> None:
        try:
            import jsonschema
        except ImportError:
            return

        if self._strict_schema:
            schema = {**schema, "additionalProperties": False}

        try:
            jsonschema.Draft7Validator(schema).validate(arguments)
        except jsonschema.ValidationError as exc:
            raise ValidationError(
                f"Tool {tool_name!r} argument schema violation: {exc.message}"
            ) from exc

    async def on_startup(self) -> None:
        pass

    async def on_session_start(self, ctx: CoSAIContext) -> CoSAIContext:
        return ctx

    async def on_request(self, ctx: CoSAIContext, req: MCPRequest) -> CoSAIContext:
        # F2 fix: validate every content-bearing method (tools/call,
        # resources/read, resources/subscribe, prompts/get) — not just
        # tools/call. resources/read.uri = file:///etc/passwd was previously
        # unscanned for path traversal / injection.
        #
        # BLOCK[1] fix: the T3-001 size-limit and the tools/call strict-schema
        # / unknown-tool gate MUST run for ANY content-bearing method,
        # independent of whether `scannable_strings` extracted any fields. A
        # `tools/call` with empty/abnormal params (no name, no arguments, no
        # uri) yields `{}` here; gating these checks on a non-empty `fields`
        # let an attacker bypass the payload-size DoS guard and the schema
        # enforcement simply by omitting the standard param keys. The
        # field-extraction result only governs the per-field injection scans
        # below, never the size/schema gates.
        is_content_method = req.method in CONTENT_BEARING_METHODS
        fields = scannable_strings(req)
        if not is_content_method and not fields:
            return ctx

        # T3-001: size limit — runs for every content-bearing method even when
        # no scannable field was extracted (empty/abnormal params).
        raw = str(req.params)
        if len(raw.encode()) > self._max_payload_bytes:
            raise ValidationError(
                f"Payload exceeds {self._max_payload_bytes} bytes"
            )

        arguments = req.params.get("arguments")
        tool_name = str(req.params.get("name", ""))

        # T3-002/003/004: reject non-dict, non-None arguments outright (cannot scan safely)
        if arguments is not None and not isinstance(arguments, dict):
            raise ValidationError(
                f"Tool {tool_name!r}: 'arguments' must be an object, "
                f"got {type(arguments).__name__}"
            )

        # Recursively scan all string values including nested lists/dicts.
        # Covers arguments AND the resources/* `uri` field (F2).
        if arguments is not None:
            self._scan_all_strings(arguments, "arguments")
        uri = fields.get("uri")
        if uri is not None:
            if not isinstance(uri, str):
                raise ValidationError(
                    f"{req.method!r}: 'uri' must be a string, got {type(uri).__name__}"
                )
            self._scan_injection(uri, "uri")

        # T3-005: JSON schema validation — only applies to tool calls; other
        # content methods have no registered input schema. Fail closed on
        # tools/call as before.
        if self._strict_schema and req.method == "tools/call":
            if tool_name not in self._tool_schemas:
                raise ValidationError(
                    f"Tool {tool_name!r} has no registered schema — "
                    "call register_tool_schemas() before dispatching (T3-005)"
                )
            schema = self._tool_schemas[tool_name]
            if schema:
                self._validate_schema(arguments or {}, schema, tool_name)

        return ctx

    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        return ctx

    async def on_session_end(self, ctx: CoSAIContext) -> None:
        pass

    async def on_shutdown(self) -> None:
        pass
