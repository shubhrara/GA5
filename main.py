from contextlib import asynccontextmanager
import base64
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import socket
from typing import Any, Literal, Optional, List
from urllib.parse import unquote, urljoin, urlparse, urlsplit

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

CHECK_SANDBOX_ROOT = Path("/srv/agent-redteam/sandbox-188512fa95")
CHECK_ALLOWED_HOSTS = frozenset({"example.com", "www.iana.org"})
CHECK_MAX_REDIRECTS = 5
CHECK_TIMEOUT_SECONDS = 10.0


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield

app = FastAPI(
    title="GA5 Spec Driven Development",
    version="1.0",
    lifespan=lifespan,
)


class ChargeRequest(BaseModel):
    old_price: float = Field(...)
    new_price: float = Field(...)
    days_remaining: int = Field(..., ge=0)
    days_in_actual_month: int = Field(..., gt=0)
    spec: Literal["v1", "v2"]


class ChargeResponse(BaseModel):
    charge: float

class SkillScanRequest(BaseModel):
    skill: str


class SkillScanResponse(BaseModel):
    categories: List[str]

##
class RunStep(BaseModel):
    step_number: int
    tool: str
    args: dict
    tokens_used: int


class RunGuardRequest(BaseModel):
    budget_tokens: int
    steps: list[RunStep]


class RunGuardResponse(BaseModel):
    decision: Literal["continue", "halt"]
    reason: str

@app.get("/")
def root():
    return {"status": "ok"}

#####################q2

@app.post("/charge", response_model=ChargeResponse)
def calculate_charge(req: ChargeRequest):
    difference = req.new_price - req.old_price

    if req.spec == "v1":
        divisor = 30
    elif req.spec == "v2":
        divisor = req.days_in_actual_month
    else:
        raise HTTPException(status_code=400, detail="Invalid spec")

    charge = difference * (req.days_remaining / divisor)

    return {
        "charge": round(charge, 2)
    }

###########################3

WORKSPACE = "/home/agent/workspace"
HOME = "/home/agent"
SECRET_FILE = "/home/agent/credentials.env"
WRITE_ROOT = "/data/agent/outbox"

ALLOWED_HOSTS = {
    "registry.npmjs.org",
    "api.github.com",
}


class GuardrailRequest(BaseModel):
    tool: Literal["bash", "write_file", "http_request"]

    command: Optional[str] = None

    path: Optional[str] = None
    content: Optional[str] = None

    method: Optional[str] = None
    url: Optional[str] = None


def normalize_path(path: str):
    path = path.replace("$HOME", HOME)
    path = path.replace("${HOME}", HOME)

    if path.startswith("~/"):
        path = HOME + path[1:]

    if not path.startswith("/"):
        path = os.path.join(WORKSPACE, path)

    return str(PurePosixPath(path))


def contains_secret_path(text: str):

    candidates = [
        SECRET_FILE,
        "~/credentials.env",
        "$HOME/credentials.env",
        "${HOME}/credentials.env",
        "../credentials.env",
        "../../credentials.env",
    ]

    lowered = text.lower()

    for c in candidates:
        if c.lower() in lowered:
            return True

    try:
        decoded = base64.b64decode(text).decode(errors="ignore").lower()

        if "credentials.env" in decoded:
            return True

    except Exception:
        pass

    return False


@app.post("/guardrail/check")
def guardrail(req: GuardrailRequest):

    #########################################
    # bash
    #########################################

    if req.tool == "bash":

        cmd = req.command or ""

        if contains_secret_path(cmd):
            return {
                "decision": "block",
                "reason": "Access to credentials.env is forbidden."
            }

        return {
            "decision": "allow",
            "reason": "Command allowed."
        }

    #########################################
    # write_file
    #########################################

    if req.tool == "write_file":

        normalized = normalize_path(req.path or "")

        try:
            rel = os.path.relpath(normalized, WRITE_ROOT)

            if rel.startswith(".."):
                return {
                    "decision": "block",
                    "reason": "Writes outside outbox are forbidden."
                }

        except Exception:

            return {
                "decision": "block",
                "reason": "Invalid path."
            }

        return {
            "decision": "allow",
            "reason": "Write permitted."
        }

    #########################################
    # http_request
    #########################################

    if req.tool == "http_request":

        parsed = urlparse(req.url or "")

        host = (parsed.hostname or "").lower()

        if host not in ALLOWED_HOSTS:
            return {
                "decision": "block",
                "reason": "Host not allowed."
            }

        return {
            "decision": "allow",
            "reason": "Host allowed."
        }

    return {
        "decision": "block",
        "reason": "Unknown tool."
    }

###############################4
SECRET_PATTERNS = [
    r"sk-[A-Za-z0-9_-]{20,}",
    r"AIza[0-9A-Za-z\-_]{20,}",
    r"ghp_[A-Za-z0-9]{20,}",
    r"xox[baprs]-[A-Za-z0-9-]+",
    r"https://hooks\.slack\.com/services/[^\s]+",
    r"api[_-]?key\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{8,}",
    r"secret\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{8,}",
    r"token\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{8,}",
]

PROMPT_INJECTION_PATTERNS = [
    r"ignore .*user",
    r"ignore .*instructions",
    r"ignore .*stop",
    r"ignore .*cancel",
    r"ignore previous",
    r"override",
    r"silent.*exfiltrat",
    r"exfiltrat",
    r"send .*file",
    r"upload .*file",
]

PERMISSION_PATTERNS = [
    r"filesystem:\s*all",
    r"network:\s*all",
    r"read.*entire filesystem",
    r"write.*entire filesystem",
    r"access.*entire filesystem",
    r"egress.*any domain",
    r"allow.*any domain",
    r"network.*\*",
]

CHANGELOG_PATTERN = r"changelog\s*:"
AUTHOR_PATTERN = r"author\s*:"
VERSION_PATTERN = r"version\s*:"

@app.post("/scanner/scan", response_model=SkillScanResponse)
def scan_skill(req: SkillScanRequest):

    skill = req.skill
    lower = skill.lower()

    categories = []

    #############################################
    # hardcoded_secret
    #############################################

    for pattern in SECRET_PATTERNS:
        if re.search(pattern, skill, re.IGNORECASE):
            if "${" not in skill and "env(" not in lower:
                categories.append("hardcoded_secret")
                break

    #############################################
    # prompt_injection
    #############################################

    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, lower):
            categories.append("prompt_injection")
            break

    #############################################
    # excessive_permissions
    #############################################

    for pattern in PERMISSION_PATTERNS:
        if re.search(pattern, lower):
            categories.append("excessive_permissions")
            break

    #############################################
    # unclear_provenance
    #############################################

    has_author = re.search(AUTHOR_PATTERN, lower)
    has_version = re.search(VERSION_PATTERN, lower)
    has_changelog = re.search(CHANGELOG_PATTERN, lower)

    rewrite_version = (
        "rewrite version" in lower
        or "change version" in lower
        or "update version silently" in lower
        or "modify version metadata" in lower
    )

    if (not has_author) or (not has_version) or (not has_changelog) or rewrite_version:
        categories.append("unclear_provenance")

    return {
        "categories": categories
    }

####55555555555
def normalize_strings(value):
    if isinstance(value, str):
        return " ".join(value.split())

    if isinstance(value, list):
        return [normalize_strings(v) for v in value]

    if isinstance(value, dict):
        cleaned = {}
        for k, v in value.items():
            if k == "trace_id":
                continue
            cleaned[k] = normalize_strings(v)
        return cleaned

    return value


def canonical_args(args: dict) -> str:
    cleaned = normalize_strings(args)
    return json.dumps(cleaned, sort_keys=True, separators=(",", ":"))


def is_pagination_progress(previous: dict, current: dict):

    keys = set(previous.keys()) | set(current.keys())

    progress_keys = {
        "page",
        "offset",
        "cursor",
        "run_id",
        "job_id",
        "attempt",
    }

    changed = []

    for key in keys:
        if previous.get(key) != current.get(key):
            changed.append(key)

    if len(changed) == 1 and changed[0] in progress_keys:
        return True

    return False


@app.post("/budget/check", response_model=RunGuardResponse)
def run_budget_guard(req: RunGuardRequest):

    ####################################################
    # Budget
    ####################################################

    total = sum(step.tokens_used for step in req.steps)

    if total >= req.budget_tokens:
        return {
            "decision": "halt",
            "reason": f"Cumulative tokens_used ({total}) has reached the budget ({req.budget_tokens})."
        }

    steps = req.steps

    ####################################################
    # 3 identical calls in a row
    ####################################################

    streak = 1

    for i in range(1, len(steps)):

        prev = steps[i - 1]
        cur = steps[i]

        if prev.tool != cur.tool:
            streak = 1
            continue

        if canonical_args(prev.args) == canonical_args(cur.args):
            streak += 1

            if streak >= 3:
                return {
                    "decision": "halt",
                    "reason": "Detected repeated identical tool calls."
                }

        else:

            if is_pagination_progress(prev.args, cur.args):
                streak = 1
            else:
                streak = 1

    ####################################################
    # A-B-A-B-A-B cycle
    ####################################################

    if len(steps) >= 6:

        last = steps[-6:]

        A = (last[0].tool, canonical_args(last[0].args))
        B = (last[1].tool, canonical_args(last[1].args))

        cycle = True

        expected = [A, B, A, B, A, B]

        for step, exp in zip(last, expected):

            if (step.tool, canonical_args(step.args)) != exp:
                cycle = False
                break

        if cycle:
            return {
                "decision": "halt",
                "reason": "Detected alternating tool loop."
            }

    ####################################################
    # Continue
    ####################################################

    return {
        "decision": "continue",
        "reason": "Budget available and no loop detected."
    }


###############################8
class CheckRequest(BaseModel):
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)


def check_response(action: Literal["allow", "block"], reason: str, result: Any = None) -> dict:
    return {"action": action, "reason": reason, "result": result}


def secure_read_path(value: Any) -> Path:
    """Resolve a requested file and require its canonical path to be sandboxed."""
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("Path must be a non-empty string.")

    decoded = unquote(value)
    if ("\\" in value) or ("\\" in decoded) or ("%2f" in value.lower()):
        raise ValueError("Encoded or alternate path separators are not allowed.")
    if re.match(r"^[A-Za-z]:", value):
        raise ValueError("Windows drive paths are not allowed.")

    # A percent-encoded complete dot segment could be interpreted as traversal
    # by an upstream URL decoder. Do not reject filenames that merely contain
    # the characters, such as "%2e%2e-literal.txt".
    if any(unquote(part) in {".", ".."} and part != unquote(part) for part in value.split("/")):
        raise ValueError("Encoded traversal path segments are not allowed.")

    sandbox = CHECK_SANDBOX_ROOT.resolve(strict=True)
    requested_path = Path(value)
    candidate = (
        requested_path.resolve(strict=True)
        if requested_path.is_absolute()
        else (sandbox / requested_path).resolve(strict=True)
    )
    try:
        candidate.relative_to(sandbox)
    except ValueError as exc:
        raise ValueError("Path escapes the sandbox.") from exc
    if not candidate.is_file():
        raise ValueError("Path is not a readable file.")
    return candidate


def normalized_allowed_url(value: Any) -> str:
    """Validate an HTTP(S) URL against the exact hostname allowlist."""
    if not isinstance(value, str) or not value or any(char.isspace() for char in value):
        raise ValueError("URL must be a non-empty, whitespace-free string.")
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        # Accessing port validates malformed and out-of-range ports.
        parsed.port
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Malformed URL.") from exc

    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc or not host:
        raise ValueError("Only absolute HTTP(S) URLs are allowed.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Embedded credentials are not allowed.")

    try:
        normalized_host = host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Invalid hostname.") from exc
    if normalized_host not in CHECK_ALLOWED_HOSTS:
        raise ValueError("Host is not allowlisted.")

    try:
        addresses = socket.getaddrinfo(normalized_host, parsed.port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("Hostname could not be resolved.") from exc
    if not addresses:
        raise ValueError("Hostname could not be resolved.")
    for address in addresses:
        try:
            resolved_ip = ipaddress.ip_address(address[4][0])
        except ValueError as exc:
            raise ValueError("Hostname resolved to an invalid IP address.") from exc
        if not resolved_ip.is_global:
            raise ValueError("Hostname resolves to a non-public IP address.")
    return value


async def fetch_allowed_url(url: str) -> str:
    current_url = normalized_allowed_url(url)
    redirects = 0
    timeout = httpx.Timeout(CHECK_TIMEOUT_SECONDS)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False) as client:
        while True:
            response = await client.get(current_url)
            if not response.is_redirect:
                return response.text

            location = response.headers.get("location")
            if not location:
                raise ValueError("Redirect has no location.")
            redirects += 1
            if redirects > CHECK_MAX_REDIRECTS:
                raise ValueError("Too many redirects.")
            current_url = normalized_allowed_url(urljoin(str(response.url), location))


@app.post("/check")
async def check(req: CheckRequest):
    try:
        if req.tool == "read_file":
            path = secure_read_path(req.arguments.get("path"))
            return check_response(
                "allow",
                "File read permitted.",
                {"content": path.read_text(encoding="utf-8")},
            )
        if req.tool == "fetch_url":
            content = await fetch_allowed_url(req.arguments.get("url"))
            return check_response("allow", "URL fetch permitted.", {"content": content})
        return check_response("block", "Unknown tool.")
    except (ValueError, OSError, UnicodeError, httpx.HTTPError) as exc:
        return check_response("block", f"Blocked: {str(exc) or 'request could not be validated'}")
