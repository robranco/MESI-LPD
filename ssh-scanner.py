#!/usr/bin/env python3
import argparse
import csv
import importlib.util
import json
import os
import re
import random
import socket
import struct
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from html import escape
from ipaddress import ip_network, ip_address
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, TextIO


LOG_BUFFER: List[Tuple[str, bool]] = []
LOG_FILE_HANDLE: Optional[TextIO] = None


def log_message(message: str, *, error: bool = False) -> None:
    stream = sys.stderr if error else sys.stdout
    print(message, file=stream)
    if LOG_FILE_HANDLE:
        if LOG_BUFFER:
            for buffered_message, _ in LOG_BUFFER:
                LOG_FILE_HANDLE.write(buffered_message + "\n")
            LOG_BUFFER.clear()
        LOG_FILE_HANDLE.write(message + "\n")
        LOG_FILE_HANDLE.flush()
    else:
        LOG_BUFFER.append((message, error))


def initialize_run_log(directory: Path, timestamp: datetime) -> Path:
    global LOG_FILE_HANDLE
    if LOG_FILE_HANDLE:
        LOG_FILE_HANDLE.close()
    log_name = timestamp.strftime("%Y_%m_%d_%H_%M") + ".log.txt"
    log_path = directory / log_name
    LOG_FILE_HANDLE = log_path.open("w", encoding="utf-8")
    for message, _ in LOG_BUFFER:
        LOG_FILE_HANDLE.write(message + "\n")
    LOG_BUFFER.clear()
    LOG_FILE_HANDLE.flush()
    return log_path


class Ansi:
    reset = "\033[0m"
    green = "\033[32m"
    red = "\033[31m"
    yellow = "\033[33m"

    @staticmethod
    def disable() -> None:
        for attr in ("reset", "green", "red", "yellow"):
            setattr(Ansi, attr, "")


class ProgressIndicator:
    def __init__(self, total: int, interval: float = 0.1) -> None:
        self.total = total
        self._interval = interval
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._active = 0
        self._started = 0
        self._completed = 0
        self._line_len = 0
        self._spinner = ["|", "/", "-", "\\"]
        self._enabled = total > 0
        self._use_cursor = sys.stdout.isatty()

    def start(self) -> None:
        if not self._enabled or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if not self._enabled or self._thread is None:
            return
        self._stop.set()
        self._thread.join()
        self._render("+", final=True)
        sys.stdout.write("\n")
        sys.stdout.flush()
        self._thread = None

    def task_started(self) -> None:
        if not self._enabled:
            return
        with self._lock:
            self._started += 1
            self._active += 1

    def task_finished(self) -> None:
        if not self._enabled:
            return
        with self._lock:
            if self._active > 0:
                self._active -= 1
            self._completed += 1

    def _stats(self) -> Tuple[int, int, int]:
        with self._lock:
            return self._active, self._started, self._completed

    def _run(self) -> None:
        idx = 0
        while not self._stop.is_set():
            symbol = self._spinner[idx]
            self._render(symbol)
            idx = (idx + 1) % len(self._spinner)
            if self._stop.wait(self._interval):
                break

    def _render(self, symbol: str, final: bool = False) -> None:
        if not self._enabled:
            return
        active, started, completed = self._stats()
        pending = max(self.total - started, 0)
        badge = symbol if not final else "+"
        line = f"[{badge}] open:{active} left:{pending} finished:{completed}/{self.total}"
        sys.stdout.write("\r" + line)
        if self._line_len > len(line):
            sys.stdout.write(" " * (self._line_len - len(line)))
        sys.stdout.write("\n")
        if not final and self._use_cursor:
            sys.stdout.write("\033[F")
        self._line_len = len(line)
        sys.stdout.flush()


@dataclass
class CipherEntry:
    name: str
    direction: str
    score: int
    color: str
    label: str
    reason: str
    reference: Optional[str] = None


@dataclass
class AlgorithmEntry:
    name: str
    score: int
    color: str
    label: str
    reason: str
    reference: Optional[str] = None


@dataclass
class ScanResult:
    host: str
    port: int
    banner: str
    version: str
    supports_ssh2: bool
    resolved_hostname: Optional[str]
    kex_algorithms: List[AlgorithmEntry]
    host_key_algorithms: List[AlgorithmEntry]
    ciphers: List[CipherEntry]
    macs_client_to_server: List[str]
    macs_server_to_client: List[str]
    first_kex_packet_follows: bool
    cve_query: Optional[str] = None
    cve_search_url: Optional[str] = None
    cve_results: List[Dict[str, Any]] = field(default_factory=list)
    duration_seconds: float = 0.0


def ensure_environment_ready() -> None:
    """Validate Python version, virtual environment activation, and dependencies."""

    minimum_version = (3, 9)
    if sys.version_info < minimum_version:
        required = f"{minimum_version[0]}.{minimum_version[1]}"
        log_message(
            f"ERROR: Python {required}+ is required. Detected {sys.version_info.major}.{sys.version_info.minor}.",
            error=True,
        )
        log_message("Please upgrade Python before running this tool.", error=True)
        sys.exit(1)

    project_root = Path(__file__).resolve().parent
    venv_dir = project_root / ".venv"
    active_venv = os.environ.get("VIRTUAL_ENV")

    venv_present = venv_dir.exists()
    if not venv_present:
        log_message(f"WARNING: Expected virtual environment directory not found at {venv_dir}.")
        log_message("You can create it with:")
        log_message("  python -m venv .venv")
        log_message("Then install requirements inside it:")
        log_message("  python -m pip install -r requirements.txt")

    interpreter_path = Path(sys.executable).resolve()
    inside_expected_venv = venv_present and venv_dir.resolve() in interpreter_path.parents
    venv_active = bool(active_venv) and Path(active_venv).resolve() == venv_dir.resolve()
    if venv_present and not (venv_active or inside_expected_venv):
        log_message("WARNING: Project virtual environment is not active.")
        if os.name == "nt":
            log_message("Activate it before running to isolate dependencies:")
            log_message("  PowerShell:  .\\.venv\\Scripts\\Activate.ps1")
            log_message("  CMD:        \\.venv\\Scripts\\activate.bat")
        else:
            log_message("Activate it before running to isolate dependencies:")
            log_message("  source .venv/bin/activate")
        log_message("Continuing with the current interpreter; ensure required packages are installed.")

    requirements_path = project_root / "requirements.txt"
    if not requirements_path.exists():
        log_message("WARNING: requirements.txt is missing. Create it (even if empty) so deployments know the dependencies.")
        return

    missing_packages: List[str] = []
    with requirements_path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            package_name = re.split(r"[<>=!;\[]", line, 1)[0].strip()
            if not package_name:
                continue
            module_name = package_name.replace("-", "_")
            if importlib.util.find_spec(module_name) is None:
                missing_packages.append(package_name)

    if missing_packages:
        log_message("WARNING: Missing packages detected in the current environment:")
        for package in missing_packages:
            log_message(f"  - {package}")
        log_message("Install them inside the virtual environment with:")
        log_message("  python -m pip install -r requirements.txt")
        log_message("Continuing execution; missing packages may cause runtime errors if referenced.")


STRONG_CIPHERS = {
    "chacha20-poly1305@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-ctr@openssh.com",
    "aes256-ctr@openssh.com",
}

WEAK_CIPHERS = {
    "3des-cbc",
    "blowfish-cbc",
    "twofish-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "cast128-cbc",
    "des-cbc",
    "des-ede3-cbc",
    "rijndael-cbc@lysator.liu.se",
    "none",
}

MAX_HOSTS_FROM_RANGE = 4096


STRONG_MACS = {
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-384-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512",
    "hmac-sha2-384",
    "hmac-sha2-256",
    "umac-128-etm@openssh.com",
    "umac-128@openssh.com",
    "umac-128",
}

WEAK_MACS = {
    "hmac-md5",
    "hmac-md5-96",
    "hmac-md5@ssh.com",
    "hmac-md5-96@ssh.com",
    "hmac-md5-etm@openssh.com",
    "hmac-md5-96-etm@openssh.com",
    "hmac-sha1",
    "hmac-sha1-96",
    "hmac-sha1@ssh.com",
    "hmac-sha1-96@ssh.com",
    "hmac-sha1-etm@openssh.com",
    "hmac-sha1-96-etm@openssh.com",
    "hmac-ripemd160",
    "umac-64@openssh.com",
    "umac-64-etm@openssh.com",
    "umac-64",
    "none",
    "crc32",
}

NIST_REFERENCES = {
    # Key exchange primitives
    "diffie-hellman-group14-sha256": "https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final",
    "diffie-hellman-group16-sha512": "https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final",
    "diffie-hellman-group18-sha512": "https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final",
    "diffie-hellman-group-exchange-sha256": "https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final",
    "ecdh-sha2-nistp256": "https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final",
    "ecdh-sha2-nistp384": "https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final",
    "ecdh-sha2-nistp521": "https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final",
    "diffie-hellman-group14-sha1": "https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final",
    "diffie-hellman-group-exchange-sha1": "https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final",
    "diffie-hellman-group1-sha1": "https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final",
    # Host key algorithms
    "rsa-sha2-256": "https://csrc.nist.gov/publications/detail/fips/186/5/final",
    "rsa-sha2-256-cert-v01@openssh.com": "https://csrc.nist.gov/publications/detail/fips/186/5/final",
    "rsa-sha2-512": "https://csrc.nist.gov/publications/detail/fips/186/5/final",
    "rsa-sha2-512-cert-v01@openssh.com": "https://csrc.nist.gov/publications/detail/fips/186/5/final",
    "ecdsa-sha2-nistp256": "https://csrc.nist.gov/publications/detail/fips/186/5/final",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com": "https://csrc.nist.gov/publications/detail/fips/186/5/final",
    "ecdsa-sha2-nistp384": "https://csrc.nist.gov/publications/detail/fips/186/5/final",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com": "https://csrc.nist.gov/publications/detail/fips/186/5/final",
    "ecdsa-sha2-nistp521": "https://csrc.nist.gov/publications/detail/fips/186/5/final",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com": "https://csrc.nist.gov/publications/detail/fips/186/5/final",
    "ssh-rsa": "https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final",
    "ssh-rsa-cert-v01@openssh.com": "https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final",
    "ssh-dss": "https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final",
    "ssh-dss-cert-v01@openssh.com": "https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final",
    # Symmetric ciphers
    "aes128-gcm@openssh.com": "https://csrc.nist.gov/publications/detail/sp/800-38d/final",
    "aes256-gcm@openssh.com": "https://csrc.nist.gov/publications/detail/sp/800-38d/final",
    "aes128-ctr": "https://csrc.nist.gov/publications/detail/sp/800-38a/final",
    "aes192-ctr": "https://csrc.nist.gov/publications/detail/sp/800-38a/final",
    "aes256-ctr": "https://csrc.nist.gov/publications/detail/sp/800-38a/final",
    "aes128-ctr@openssh.com": "https://csrc.nist.gov/publications/detail/sp/800-38a/final",
    "aes256-ctr@openssh.com": "https://csrc.nist.gov/publications/detail/sp/800-38a/final",
    "aes128-cbc": "https://csrc.nist.gov/publications/detail/sp/800-38a/final",
    "aes192-cbc": "https://csrc.nist.gov/publications/detail/sp/800-38a/final",
    "aes256-cbc": "https://csrc.nist.gov/publications/detail/sp/800-38a/final",
    "3des-cbc": "https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final",
    "des-ede3-cbc": "https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final",
    "des-cbc": "https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final",
}


def lookup_nist_reference(name: str) -> Optional[str]:
    """Return the NIST reference URL for the given algorithm name, if known."""

    return NIST_REFERENCES.get(name.lower())


def blend_channel(start: int, end: int, factor: float) -> int:
    return int(round(start + (end - start) * factor))


def blend_colors(start_hex: str, end_hex: str, factor: float) -> str:
    factor = max(0.0, min(1.0, factor))
    start = int(start_hex.lstrip("#"), 16)
    end = int(end_hex.lstrip("#"), 16)
    sr, sg, sb = (start >> 16) & 0xFF, (start >> 8) & 0xFF, start & 0xFF
    er, eg, eb = (end >> 16) & 0xFF, (end >> 8) & 0xFF, end & 0xFF
    r = blend_channel(sr, er, factor)
    g = blend_channel(sg, eg, factor)
    b = blend_channel(sb, eb, factor)
    return f"#{r:02x}{g:02x}{b:02x}"


def color_for_score(value: float, min_value: float, max_value: float) -> str:
    worst_color = "#d32f2f"
    mid_color = "#fbc02d"
    best_color = "#66bb6a"

    if max_value == min_value:
        return best_color if value >= 0 else worst_color

    normalized = (value - min_value) / (max_value - min_value)
    normalized = max(0.0, min(1.0, normalized))

    if normalized < 0.5:
        return blend_colors(worst_color, mid_color, normalized / 0.5)
    return blend_colors(mid_color, best_color, (normalized - 0.5) / 0.5)


LABEL_COLORS = {
    "strong": "#66bb6a",
    "intermediate": "#fdd835",
    "weak": "#ef5350",
}

LABEL_PRIORITY = {
    "weak": 0,
    "intermediate": 1,
    "strong": 2,
}

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "NONE": 4,
    "UNKNOWN": 5,
}


def extract_host_key_size(name: str) -> str:
    """Derive an approximate key size label from a host key algorithm name."""

    normalized = name.lower()
    mapping = (
        ("sk-ssh-ed25519", "256-bit"),
        ("ssh-ed25519", "256-bit"),
        ("sk-ecdsa-sha2-nistp256", "256-bit"),
        ("ecdsa-sha2-nistp256", "256-bit"),
        ("ecdsa-sha2-nistp384", "384-bit"),
        ("ecdsa-sha2-nistp521", "521-bit"),
        ("rsa-sha2-256", ">=2048-bit"),
        ("rsa-sha2-512", ">=2048-bit"),
        ("ssh-rsa", ">=1024-bit"),
        ("ssh-dss", "1024-bit"),
    )
    for prefix, label in mapping:
        if normalized.startswith(prefix):
            return label

    digits = "".join(ch for ch in name if ch.isdigit())
    if digits:
        return f"{digits}-bit"
    return "Unknown"


def extract_cipher_key_bits(name: str) -> int:
    lower = name.lower()
    digits = [int(token) for token in re.findall(r"(\d{2,4})", lower)]
    if "chacha20" in lower:
        digits.append(256)
    return max(digits) if digits else 0


def classify_mac(name: str) -> Tuple[int, str]:
    lower = name.lower()

    if lower in STRONG_MACS or (
        "etm@openssh.com" in lower and ("sha2" in lower or "umac-128" in lower)
    ):
        return 0, "strong"

    if lower in WEAK_MACS or "md5" in lower or "sha1" in lower or lower.endswith("-96") or lower == "none" or "crc" in lower:
        return 2, "weak"

    return 1, "intermediate"


def mac_sort_key(name: str) -> Tuple[int, int, str]:
    score, _ = classify_mac(name)
    lower = name.lower()

    digest_metric = 8
    if "sha512" in lower or "sha2-512" in lower:
        digest_metric = 0
    elif "sha384" in lower or "sha2-384" in lower:
        digest_metric = 1
    elif "sha256" in lower or "sha2-256" in lower:
        digest_metric = 2
    elif "sha224" in lower or "sha2-224" in lower:
        digest_metric = 3
    elif "umac-128" in lower:
        digest_metric = 2
    elif "sha1" in lower:
        digest_metric = 5
    elif "umac-64" in lower or "ripemd" in lower:
        digest_metric = 6
    elif "md5" in lower:
        digest_metric = 7

    if "etm@openssh.com" in lower:
        digest_metric = max(0, digest_metric - 1)

    return score, digest_metric, lower


def cipher_aggregate_sort_key(name: str, count: int, label: str) -> Tuple[int, int, int, str]:
    priority = LABEL_PRIORITY.get(label, 1)
    bits = extract_cipher_key_bits(name)
    return (-priority, -bits, -count, name)


def estimate_kex_strength(name: str) -> int:
    lower = name.lower()
    group_map = {
        "group18": 8192,
        "group17": 6144,
        "group16": 4096,
        "group15": 3072,
        "group14": 2048,
        "group13": 3072,
        "group1": 1024,
    }
    for token, strength in group_map.items():
        if token in lower:
            return strength

    if "sntrup" in lower or "sntru" in lower or "ntru" in lower or "kyber" in lower or "mlkem" in lower:
        return 256

    match = re.search(r"curve(\d+)", lower)
    if match:
        return int(match.group(1))

    match = re.search(r"nistp(\d+)", lower)
    if match:
        return int(match.group(1))

    digits = [int(value) for value in re.findall(r"(\d{2,5})", lower)]
    if digits:
        return max(digits)

    return 0


def algorithm_aggregate_sort_key(name: str, count: int, label: str) -> Tuple[int, int, int, str]:
    priority = LABEL_PRIORITY.get(label, 1)
    strength = estimate_kex_strength(name)
    return (-priority, -strength, -count, name)


def build_cve_query_from_banner(banner: str) -> Optional[str]:
    """Attempt to derive a CVE search query from the SSH banner."""

    match = re.search(r"openssh[_-]?([0-9][0-9a-zA-Z\.p-]*)", banner, re.IGNORECASE)
    if match:
        version = match.group(1).replace("_", " ")
        return f"OpenSSH {version}".strip()

    match = re.search(r"dropbear[_-]?ssh[_-]?([0-9][0-9a-zA-Z\.p-]*)", banner, re.IGNORECASE)
    if match:
        version = match.group(1).replace("_", " ")
        return f"Dropbear SSH {version}".strip()

    match = re.search(r"libssh[_-]?([0-9][0-9a-zA-Z\.p-]*)", banner, re.IGNORECASE)
    if match:
        version = match.group(1).replace("_", " ")
        return f"libssh {version}".strip()

    generic = re.search(r"^SSH-[0-9.]+-([A-Za-z0-9][A-Za-z0-9_\-\.]+)(.*)$", banner.strip())
    if generic:
        product_token = generic.group(1)
        remainder = generic.group(2)
        version_token = None
        for token in re.split(r"[\s/]+", remainder):
            if any(ch.isdigit() for ch in token):
                version_token = token
                break
        if version_token is None and any(ch.isdigit() for ch in product_token):
            version_token = product_token
        name_token = product_token
        name_clean = re.sub(r"[_-]+", " ", name_token).strip()
        version_clean = re.sub(r"[_-]+", " ", version_token).strip() if version_token else ""
        if name_clean and version_clean:
            return f"{name_clean} {version_clean}".strip()
        if name_clean:
            return name_clean

    return None


def lookup_cves_for_banner(banner: str, max_results: int, timeout: float) -> Tuple[List[Dict[str, Any]], Optional[str], Optional[str]]:
    """Fetch CVE entries related to the banner using the NVD API, if possible."""

    query = build_cve_query_from_banner(banner)
    if not query or max_results <= 0:
        return [], None, query

    encoded_query = urllib.parse.quote(query)
    api_url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage={}&keywordSearch={}".format(
            max(1, min(max_results, 200)), encoded_query
        )
    )
    search_page = f"https://nvd.nist.gov/vuln/search/results?query={encoded_query}"
    request = urllib.request.Request(api_url, headers={"User-Agent": "ssh-scanner/1.0"})

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, socket.timeout, json.JSONDecodeError):
        return [], search_page, query

    items: List[Dict[str, Any]] = []
    for entry in payload.get("vulnerabilities", []):
        cve = entry.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        summary = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en" and desc.get("value"):
                summary = desc["value"]
                break
        metrics = cve.get("metrics") or {}
        severity = ""
        base_score: Optional[float] = None
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key)
            if not metric_list:
                continue
            metric_entry = metric_list[0]
            data = metric_entry.get("cvssData", {})
            raw_score = data.get("baseScore")
            if raw_score is None:
                raw_score = metric_entry.get("baseScore")
            if isinstance(raw_score, str):
                try:
                    base_score = float(raw_score)
                except ValueError:
                    base_score = None
            elif isinstance(raw_score, (int, float)):
                base_score = float(raw_score)
            raw_severity = data.get("baseSeverity") or metric_entry.get("baseSeverity")
            severity = raw_severity.upper() if isinstance(raw_severity, str) else ""
            break
        items.append(
            {
                "id": cve_id,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "summary": summary,
                "severity": severity,
                "score": base_score,
            }
        )
        if len(items) >= max_results:
            break

    return items, search_page, query


CIPHER_REASONS = {
    "chacha20-poly1305@openssh.com": "2013/2014 AEAD design with 256-bit key and Poly1305 authenticator; resists known attacks as of 2025.",
    "aes128-gcm@openssh.com": "AES-128 (2001) in GCM mode (2007) offering authenticated encryption with 128-bit security.",
    "aes256-gcm@openssh.com": "AES-256 (2001) in GCM mode (2007) providing AEAD and 256-bit security margin.",
    "aes128-ctr": "AES-128 (2001) in CTR mode; 128-bit key remains strong when paired with modern MACs.",
    "aes192-ctr": "AES-192 (2001) in CTR mode; extended key length offers strong margin.",
    "aes256-ctr": "AES-256 (2001) in CTR mode; 256-bit key gives long-term strength.",
    "aes128-ctr@openssh.com": "OpenSSH variant of AES-128 CTR (2001); still secure with 128-bit key.",
    "aes256-ctr@openssh.com": "OpenSSH variant of AES-256 CTR (2001); 256-bit key for high assurance.",
    "3des-cbc": "Triple DES (late 1990s) with 112-bit effective security and 64-bit block; vulnerable to SWEET32 and slow.",
    "blowfish-cbc": "Blowfish (1993) with 64-bit block size; susceptible to SWEET32-style attacks.",
    "twofish-cbc": "Twofish (1998) but used in CBC without authentication; better options exist today.",
    "arcfour": "RC4 (1987) with severe keystream biases discovered in 2000s; deprecated since 2013.",
    "arcfour128": "RC4 variant (1987) limited to 128 bits but still biased; prohibited by modern guidance.",
    "arcfour256": "RC4 variant (1987) with longer key but same statistical weaknesses; deprecated.",
    "aes128-cbc": "AES-128 (2001) in CBC mode; prone to padding-oracle attacks without extra mitigations.",
    "aes192-cbc": "AES-192 (2001) in CBC mode; same padding-oracle issues reduce safety.",
    "aes256-cbc": "AES-256 (2001) in CBC mode; padding oracles and lack of integrity make it risky.",
    "cast128-cbc": "CAST-128 (1996) with 64-bit block; outdated and affected by SWEET32 risks.",
    "des-cbc": "Single DES (1977) with 56-bit key; brute-force feasible since late 1990s.",
    "des-ede3-cbc": "Triple DES (late 1990s) with 112-bit security but 64-bit blocks and slow performance.",
    "rijndael-cbc@lysator.liu.se": "Rijndael precursor to AES (1998) in CBC mode; lacks AEAD protections.",
    "none": "No encryption layer; exposes plaintext over the network.",
}

DEFAULT_STRONG_REASON = "Post-2010 design with >=128-bit keys and authenticated or counter mode; no practical attacks reported by 2025."
DEFAULT_INTERMEDIATE_REASON = "Early-2000s era construction without built-in authentication; acceptable today but upgrade to AEAD soon."
DEFAULT_WEAK_REASON = "Older (pre-2005) design with limited block size or known attacks (e.g., padding or keystream biases)."

STRONG_KEX = {
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "sntrup761x25519-sha512@openssh.com",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group-exchange-sha256",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
}

INTERMEDIATE_KEX = {
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
}

WEAK_KEX = {
    "diffie-hellman-group1-sha1",
}

KEX_REASONS = {
    "curve25519-sha256": "Curve25519 (2014) + SHA-256; ~128-bit strength matching NIST SP 800-57 Level 1 guidance.",
    "curve25519-sha256@libssh.org": "Libssh.org Curve25519 (2014) w/ SHA-256; aligns with NIST >=128-bit recommendations.",
    "sntrup761x25519-sha512@openssh.com": "Hybrid NTRU Prime 761 + X25519 (2020) with SHA-512, exceeding NIST Level 1 minimums.",
    "diffie-hellman-group14-sha256": "2048-bit MODP Group14 + SHA-256 (2014 refresh) satisfies NIST 112-bit baseline.",
    "diffie-hellman-group16-sha512": "4096-bit MODP Group16 + SHA-512 exceeds NIST Level 1 (112-bit) recommendations.",
    "diffie-hellman-group18-sha512": "8192-bit MODP Group18 + SHA-512 provides Level 2+ margin per NIST SP 800-57.",
    "diffie-hellman-group-exchange-sha256": "RFC 4419 (2006) DH with negotiated >=2048-bit primes and SHA-256; meets NIST baseline.",
    "ecdh-sha2-nistp256": "ECDH on NIST P-256 (2009) ~128-bit strength as required by NIST for Level 1.",
    "ecdh-sha2-nistp384": "ECDH on NIST P-384 (2009) ~192-bit, aligning with NIST Level 2 guidance.",
    "ecdh-sha2-nistp521": "ECDH on NIST P-521 (2009) ~256-bit, meeting NIST Level 3 goals.",
    "diffie-hellman-group14-sha1": "2048-bit Group14 (2002) but SHA-1 hashing; marginal vs NIST guidance due to hash aging.",
    "diffie-hellman-group-exchange-sha1": "Negotiated DH with SHA-1 (2006); migrate to SHA-256 for NIST compliance.",
    "diffie-hellman-group1-sha1": "1024-bit Group1 + SHA-1 (1997); below NIST 112-bit minimum and considered broken.",
}

DEFAULT_STRONG_KEX_REASON = "Meets or exceeds NIST SP 800-57 Level 1 (>=112-bit) using SHA-2 family primitives."
DEFAULT_INTERMEDIATE_KEX_REASON = "At or near NIST minimums but held back by SHA-1 reliance; upgrade recommended."
DEFAULT_WEAK_KEX_REASON = "Falls below NIST 112-bit baseline or uses SHA-1 exclusively; treat as deprecated."

STRONG_HOST_KEYS = {
    "ssh-ed25519",
    "ssh-ed25519-cert-v01@openssh.com",
    "sk-ssh-ed25519@openssh.com",
    "sk-ssh-ed25519-cert-v01@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp521",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    "rsa-sha2-256",
    "rsa-sha2-256-cert-v01@openssh.com",
    "rsa-sha2-512",
    "rsa-sha2-512-cert-v01@openssh.com",
}

WEAK_HOST_KEYS = {
    "ssh-rsa",
    "ssh-rsa-cert-v01@openssh.com",
    "ssh-dss",
    "ssh-dss-cert-v01@openssh.com",
}

HOST_KEY_REASONS = {
    "ssh-ed25519": "Ed25519 (2014) ~128-bit strength with SHA-512; exceeds NIST Level 1 recommendations.",
    "ssh-ed25519-cert-v01@openssh.com": "Certificate Ed25519 (2014) + SHA-512; NIST-compliant modern default.",
    "sk-ssh-ed25519@openssh.com": "FIDO2 Ed25519 (2019) hardware-backed, satisfying NIST >=128-bit guidance.",
    "sk-ssh-ed25519-cert-v01@openssh.com": "FIDO2 Ed25519 cert (2019) + SHA-512; strong per NIST Level 1.",
    "sk-ecdsa-sha2-nistp256@openssh.com": "FIDO2 ECDSA P-256 (2019) with SHA-256; meets NIST Level 1.",
    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com": "FIDO2 ECDSA P-256 cert (2019); NIST Level 1 compliant.",
    "ecdsa-sha2-nistp256": "ECDSA P-256 (2009) ~128-bit strength per NIST Level 1.",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com": "ECDSA P-256 cert (2009); meets NIST Level 1.",
    "ecdsa-sha2-nistp384": "ECDSA P-384 (2009) ~192-bit security, exceeding NIST Level 2 baseline.",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com": "ECDSA P-384 cert (2009) ~192-bit; NIST Level 2 ready.",
    "ecdsa-sha2-nistp521": "ECDSA P-521 (2009) ~256-bit, aligned with NIST Level 3.",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com": "ECDSA P-521 cert (2009) ~256-bit; NIST Level 3.",
    "rsa-sha2-256": "RSA with SHA-256 (2018); requires >=2048-bit keys to satisfy NIST Level 1.",
    "rsa-sha2-256-cert-v01@openssh.com": "Certificate RSA + SHA-256 (2018); compliant for >=2048-bit keys.",
    "rsa-sha2-512": "RSA with SHA-512 (2018); strong hash and >=2048-bit RSA meets NIST Level 1.",
    "rsa-sha2-512-cert-v01@openssh.com": "Certificate RSA + SHA-512 (2018); strong per NIST Level 1.",
    "ssh-rsa": "RSA with SHA-1 (2006); fails NIST guidance due to SHA-1 collisions.",
    "ssh-rsa-cert-v01@openssh.com": "Certificate RSA SHA-1 (2006); non-compliant with NIST mandates.",
    "ssh-dss": "DSA limited to 1024-bit modulus (1994); below NIST minimum 112-bit strength.",
    "ssh-dss-cert-v01@openssh.com": "DSA 1024-bit cert (1994); deprecated under NIST guidance.",
}

DEFAULT_STRONG_HOST_REASON = "Meets NIST SP 800-57 Level 1 (>=2048-bit RSA or >=128-bit ECC) with SHA-2/Ed25519."
DEFAULT_INTERMEDIATE_HOST_REASON = "Near NIST baseline but missing SHA-2 or hardware assurances; migrate soon."
DEFAULT_WEAK_HOST_REASON = "Below NIST minimum strength or uses SHA-1; treat as deprecated."

DEFAULT_PQC_KEX_REASON = "Includes post-quantum or hybrid key exchange; treated as strong pending formal guidance."
DEFAULT_PQC_HOST_REASON = "Post-quantum or hybrid host key mechanism; treated as strong until standards mature."


def parse_host_port(value: str, default_port: int) -> Tuple[str, int]:
    token = value.strip()
    if not token:
        return "", default_port

    if token.startswith("["):
        end_bracket = token.find("]")
        if end_bracket == -1:
            raise ValueError(f"Invalid host format '{value}' (missing closing bracket).")
        host = token[1:end_bracket]
        remainder = token[end_bracket + 1 :]
        if remainder.startswith(":"):
            port_part = remainder[1:]
            if not port_part:
                raise ValueError(f"Missing port after host in '{value}'.")
            try:
                port = int(port_part)
            except ValueError as exc:
                raise ValueError(f"Invalid port '{port_part}' in '{value}'.") from exc
            if port <= 0 or port > 65535:
                raise ValueError(f"Port out of range in '{value}'.")
            return host, port
        if remainder:
            raise ValueError(f"Invalid host format '{value}'.")
        return host, default_port

    if ":" in token:
        host_part, port_part = token.rsplit(":", 1)
        if port_part.isdigit():
            port = int(port_part)
            if port <= 0 or port > 65535:
                raise ValueError(f"Port out of range in '{value}'.")
            return host_part, port

    return token, default_port


def expand_target_entry(entry: str, default_port: int) -> List[Tuple[str, int]]:
    raw_target = entry.split("#", 1)[0].strip()
    if not raw_target:
        return []

    host_token, port = parse_host_port(raw_target, default_port)

    try:
        network = ip_network(host_token, strict=False)
    except ValueError:
        return [(host_token, port)]

    if network.num_addresses > MAX_HOSTS_FROM_RANGE:
        raise ValueError(
            f"Network {host_token} expands to {network.num_addresses} addresses; limit is {MAX_HOSTS_FROM_RANGE}."
        )

    if network.num_addresses <= 1:
        return [(str(network.network_address), port)]

    hosts = [str(host) for host in network.hosts()]
    hosts = hosts or [str(network.network_address)]
    return [(host, port) for host in hosts]


def collect_targets(args: argparse.Namespace, default_port: int) -> List[Tuple[str, int]]:
    entries: List[str] = []
    if args.target:
        entries.append(args.target)
    if args.range:
        entries.append(args.range)
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as handler:
                for line in handler:
                    entries.append(line.strip())
        except OSError as exc:
            raise ValueError(f"Could not read {args.file}: {exc}") from exc

    seen: Set[Tuple[str, int]] = set()
    targets: List[Tuple[str, int]] = []
    for item in entries:
        for target in expand_target_entry(item, default_port):
            if target[0] and target not in seen:
                targets.append(target)
                seen.add(target)
    if targets and getattr(args, "randomize_order", True):
        random.SystemRandom().shuffle(targets)
    return targets


def receive_banner(sock: socket.socket, timeout: float) -> str:
    sock.settimeout(timeout)
    data = bytearray()
    while not data.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > 1024:
            raise RuntimeError("SSH banner exceeded 1 KiB without a newline.")
    return data.decode("ascii", errors="replace").strip()


def send_banner(sock: socket.socket) -> None:
    sock.sendall(b"SSH-2.0-SSHScanner\r\n")


def receive_packet(sock: socket.socket, timeout: float) -> bytes:
    sock.settimeout(timeout)
    header = _recv_exact(sock, 4)
    packet_length = struct.unpack(">I", header)[0]
    if packet_length > 35000:
        raise RuntimeError(f"Unexpectedly large packet ({packet_length} bytes).")
    padding_length = _recv_exact(sock, 1)[0]
    payload_len = packet_length - padding_length - 1
    payload = _recv_exact(sock, payload_len)
    _recv_exact(sock, padding_length)  # discard padding bytes
    return payload


def _recv_exact(sock: socket.socket, nbytes: int) -> bytes:
    data = bytearray()
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise RuntimeError("Connection closed prematurely.")
        data.extend(chunk)
    return bytes(data)


def read_name_list(buffer: bytes, offset: int) -> Tuple[List[str], int]:
    size = struct.unpack(">I", buffer[offset:offset + 4])[0]
    offset += 4
    value = buffer[offset:offset + size].decode("ascii", errors="replace")
    offset += size
    return (value.split(",")) if value else [], offset


def parse_kexinit(payload: bytes) -> dict:
    if not payload or payload[0] != 20:  # SSH_MSG_KEXINIT
        raise RuntimeError("First packet is not SSH_MSG_KEXINIT.")
    idx = 1 + 16  # skip message type and cookie
    fields = {}
    fields["kex_algorithms"], idx = read_name_list(payload, idx)
    fields["server_host_key_algorithms"], idx = read_name_list(payload, idx)
    fields["encryption_algorithms_client_to_server"], idx = read_name_list(payload, idx)
    fields["encryption_algorithms_server_to_client"], idx = read_name_list(payload, idx)
    fields["mac_algorithms_client_to_server"], idx = read_name_list(payload, idx)
    fields["mac_algorithms_server_to_client"], idx = read_name_list(payload, idx)
    fields["compression_algorithms_client_to_server"], idx = read_name_list(payload, idx)
    fields["compression_algorithms_server_to_client"], idx = read_name_list(payload, idx)
    fields["languages_client_to_server"], idx = read_name_list(payload, idx)
    fields["languages_server_to_client"], idx = read_name_list(payload, idx)
    fields["first_kex_packet_follows"] = bool(payload[idx])
    return fields


def classify_version(banner: str) -> str:
    if banner.startswith("SSH-1."):
        return "SSH v1"
    if banner.startswith("SSH-1.99"):
        return "SSH v2 (server also accepts v1)"
    if banner.startswith("SSH-2.") or banner.startswith("SSH-2"):
        return "SSH v2"
    return "Version not recognized"


def infer_platform_insight(banner: str) -> str:
    lower = banner.lower()
    parts: List[str] = []

    manufacturer_map = {
        "cisco": "Manufacturer: Cisco",
        "fortinet": "Manufacturer: Fortinet",
        "fortigate": "Manufacturer: Fortinet",
        "juniper": "Manufacturer: Juniper Networks",
        "palo alto": "Manufacturer: Palo Alto Networks",
        "pan-os": "Manufacturer: Palo Alto Networks",
        "checkpoint": "Manufacturer: Check Point",
        "sonicwall": "Manufacturer: SonicWall",
        "f5": "Manufacturer: F5 Networks",
        "big-ip": "Manufacturer: F5 Networks",
        "mikrotik": "Manufacturer: MikroTik",
        "huawei": "Manufacturer: Huawei",
        "aruba": "Manufacturer: Aruba Networks",
    }
    for keyword, label in manufacturer_map.items():
        if keyword in lower:
            parts.append(label)
            break

    if "openssh" in lower:
        match = re.search(r"OpenSSH[_-]?([0-9][0-9a-zA-Z\.p-]*)", banner, re.IGNORECASE)
        version = match.group(1) if match else ""
        component = f"OpenSSH {version}".strip()
        parts.append(component if component else "OpenSSH detected")
    if "dropbear" in lower:
        match = re.search(r"Dropbear[_-]?SSH[_-]?([0-9][0-9a-zA-Z\.p-]*)", banner, re.IGNORECASE)
        version = match.group(1) if match else ""
        component = f"Dropbear SSH {version}".strip()
        parts.append(component if component else "Dropbear SSH detected")
    if "libssh" in lower:
        match = re.search(r"libssh[_-]?([0-9][0-9a-zA-Z\.p-]*)", banner, re.IGNORECASE)
        version = match.group(1) if match else ""
        component = f"libssh {version}".strip()
        parts.append(component if component else "libssh detected")

    os_map = {
        "ubuntu": "OS: Ubuntu",
        "debian": "OS: Debian",
        "centos": "OS: CentOS",
        "redhat": "OS: Red Hat Enterprise Linux",
        "red hat": "OS: Red Hat Enterprise Linux",
        "rhel": "OS: Red Hat Enterprise Linux",
        "suse": "OS: SUSE Linux",
        "opensuse": "OS: openSUSE",
        "fedora": "OS: Fedora",
        "alpine": "OS: Alpine Linux",
        "openbsd": "OS: OpenBSD",
        "freebsd": "OS: FreeBSD",
        "hp-ux": "OS: HP-UX",
        "hpux": "OS: HP-UX",
        "aix": "OS: IBM AIX",
        "solaris": "OS: Solaris",
        "sunos": "OS: Solaris",
        "windows": "OS: Windows",
        "vyatta": "OS: Vyatta",
        "fortios": "OS: FortiOS",
        "pan-os": "OS: PAN-OS",
        "ios": "OS: Cisco IOS/IOS-XE",
        "nx-os": "OS: Cisco NX-OS",
    }
    for keyword, label in os_map.items():
        if keyword in lower:
            parts.append(label)
            break

    if "linux" in lower and not any("OS:" in entry for entry in parts):
        parts.append("OS: Linux (banner reference)")

    if not parts:
        return "Unknown"
    return "; ".join(dict.fromkeys(parts))


def classify_cipher(name: str) -> Tuple[int, str, str, str]:
    name_lower = name.lower()

    if name_lower in STRONG_CIPHERS or name_lower.endswith("-gcm@openssh.com"):
        reason = CIPHER_REASONS.get(name_lower, DEFAULT_STRONG_REASON)
        return 0, Ansi.green, "strong", reason

    if (
        name_lower in WEAK_CIPHERS
        or name_lower.endswith("-cbc")
        or name_lower.startswith("arcfour")
        or name_lower.startswith("3des")
    ):
        reason = CIPHER_REASONS.get(name_lower, DEFAULT_WEAK_REASON)
        return 2, Ansi.red, "weak", reason

    if name_lower.endswith("-ctr") and name_lower.startswith("aes"):
        reason = CIPHER_REASONS.get(name_lower, DEFAULT_STRONG_REASON)
        return 0, Ansi.green, "strong", reason

    reason = CIPHER_REASONS.get(name_lower, DEFAULT_INTERMEDIATE_REASON)
    return 1, Ansi.yellow, "intermediate", reason


def cipher_sort_key(name: str) -> Tuple[int, int, int, str]:
    score, _, _, _ = classify_cipher(name)
    name_lower = name.lower()
    category_rank = 0

    if score == 0:
        if "poly1305" in name_lower:
            category_rank = 0
        elif "gcm" in name_lower:
            category_rank = 1
        elif name_lower.endswith("-ctr"):
            category_rank = 2
        else:
            category_rank = 3
    elif score == 1:
        if name_lower.endswith("-ctr") or "gcm" in name_lower:
            category_rank = 1
        else:
            category_rank = 2
    else:
        category_rank = 0

    key_bits = extract_cipher_key_bits(name_lower)
    return score, category_rank, -key_bits, name_lower


def classify_kex(name: str) -> Tuple[int, str, str, str]:
    name_lower = name.lower()

    if name_lower in STRONG_KEX:
        reason = KEX_REASONS.get(name_lower, DEFAULT_STRONG_KEX_REASON)
        return 0, Ansi.green, "strong", reason

    if name_lower in INTERMEDIATE_KEX:
        reason = KEX_REASONS.get(name_lower, DEFAULT_INTERMEDIATE_KEX_REASON)
        return 1, Ansi.yellow, "intermediate", reason

    if name_lower in WEAK_KEX:
        reason = KEX_REASONS.get(name_lower, DEFAULT_WEAK_KEX_REASON)
        return 2, Ansi.red, "weak", reason

    if any(token in name_lower for token in ("sntrup", "sntru", "ntru", "mlkem", "kyber", "pq-", "pqc", "post-quantum", "hybrid")):
        reason = KEX_REASONS.get(name_lower, DEFAULT_PQC_KEX_REASON)
        return 0, Ansi.green, "strong", reason

    if any(token in name_lower for token in ("curve25519", "sha256", "sha512", "nistp")):
        reason = KEX_REASONS.get(name_lower, DEFAULT_STRONG_KEX_REASON)
        return 0, Ansi.green, "strong", reason

    if name_lower.endswith("sha1"):
        reason = KEX_REASONS.get(name_lower, DEFAULT_WEAK_KEX_REASON)
        return 2, Ansi.red, "weak", reason

    reason = KEX_REASONS.get(name_lower, DEFAULT_INTERMEDIATE_KEX_REASON)
    return 1, Ansi.yellow, "intermediate", reason


def classify_host_key(name: str) -> Tuple[int, str, str, str]:
    name_lower = name.lower()

    if name_lower in STRONG_HOST_KEYS:
        reason = HOST_KEY_REASONS.get(name_lower, DEFAULT_STRONG_HOST_REASON)
        return 0, Ansi.green, "strong", reason

    if name_lower in WEAK_HOST_KEYS:
        reason = HOST_KEY_REASONS.get(name_lower, DEFAULT_WEAK_HOST_REASON)
        return 2, Ansi.red, "weak", reason

    if (
        name_lower.startswith("ssh-ed25519")
        or name_lower.startswith("sk-")
        or name_lower.endswith("-sha512")
        or name_lower.endswith("-sha256")
    ):
        reason = HOST_KEY_REASONS.get(name_lower, DEFAULT_STRONG_HOST_REASON)
        return 0, Ansi.green, "strong", reason

    if any(token in name_lower for token in ("dilithium", "falcon", "sphincs", "ml-dsa", "mlkem", "pqc", "pq-")):
        reason = HOST_KEY_REASONS.get(name_lower, DEFAULT_PQC_HOST_REASON)
        return 0, Ansi.green, "strong", reason

    if name_lower.endswith("-sha1") or name_lower.endswith("dss") or name_lower == "ssh-rsa":
        reason = HOST_KEY_REASONS.get(name_lower, DEFAULT_WEAK_HOST_REASON)
        return 2, Ansi.red, "weak", reason

    reason = HOST_KEY_REASONS.get(name_lower, DEFAULT_INTERMEDIATE_HOST_REASON)
    return 1, Ansi.yellow, "intermediate", reason


def scan_target(
    host: str,
    port: int,
    timeout: float,
    lookup_cves: bool = False,
    max_cves: int = 0,
    resolve_hostname: bool = True,
) -> ScanResult:
    start_marker = time.perf_counter()
    resolved_hostname: Optional[str] = None
    with socket.create_connection((host, port), timeout=timeout) as sock:
        if resolve_hostname:
            try:
                peer_ip = sock.getpeername()[0]
                resolved_hostname = socket.gethostbyaddr(peer_ip)[0]
            except (OSError, socket.herror, socket.gaierror, UnicodeError):
                resolved_hostname = None

        banner = receive_banner(sock, timeout)
        version = classify_version(banner)
        supports_ssh2 = banner.startswith(("SSH-2.", "SSH-1.99"))

        cve_results: List[Dict[str, Any]] = []
        cve_search_url: Optional[str] = None
        cve_query: Optional[str] = None
        if lookup_cves:
            cve_results, cve_search_url, cve_query = lookup_cves_for_banner(banner, max_cves, timeout)

        if not supports_ssh2:
            legacy_reason = (
                "Server only advertises SSH v1; treat all negotiated primitives as weak until SSH v2 is enabled."
            )
            legacy_kex = AlgorithmEntry(
                name="ssh-v1-legacy-kex",
                score=2,
                color=Ansi.red,
                label="weak",
                reason=legacy_reason,
                reference=None,
            )
            legacy_host_key = AlgorithmEntry(
                name="ssh-v1-legacy-host-key",
                score=2,
                color=Ansi.red,
                label="weak",
                reason=legacy_reason,
                reference=None,
            )
            legacy_cipher_client = CipherEntry(
                name="ssh-v1-cipher",
                direction="client->server",
                score=2,
                color=Ansi.red,
                label="weak",
                reason=legacy_reason,
                reference=None,
            )
            legacy_cipher_server = CipherEntry(
                name="ssh-v1-cipher",
                direction="server->client",
                score=2,
                color=Ansi.red,
                label="weak",
                reason=legacy_reason,
                reference=None,
            )
            elapsed = time.perf_counter() - start_marker
            return ScanResult(
                host=host,
                port=port,
                banner=banner,
                version=version,
                supports_ssh2=False,
                resolved_hostname=resolved_hostname,
                kex_algorithms=[legacy_kex],
                host_key_algorithms=[legacy_host_key],
                ciphers=[legacy_cipher_client, legacy_cipher_server],
                macs_client_to_server=[],
                macs_server_to_client=[],
                first_kex_packet_follows=False,
                cve_query=cve_query,
                cve_search_url=cve_search_url,
                cve_results=cve_results,
                duration_seconds=elapsed,
            )

        send_banner(sock)
        try:
            payload = receive_packet(sock, timeout)
        except RuntimeError as exc:
            raise RuntimeError(f"Failed to read SSH_MSG_KEXINIT: {exc}") from exc

        fields = parse_kexinit(payload)
        fields["mac_algorithms_client_to_server"] = sorted(
            fields["mac_algorithms_client_to_server"],
            key=mac_sort_key,
        )
        fields["mac_algorithms_server_to_client"] = sorted(
            fields["mac_algorithms_server_to_client"],
            key=mac_sort_key,
        )

        kex_entries: List[AlgorithmEntry] = []
        for alg in fields["kex_algorithms"]:
            score, color, label, reason = classify_kex(alg)
            reference = lookup_nist_reference(alg)
            kex_entries.append(
                AlgorithmEntry(alg, score, color, label, reason, reference)
            )
        kex_entries.sort(key=lambda entry: entry.score)

        host_entries: List[AlgorithmEntry] = []
        for alg in fields["server_host_key_algorithms"]:
            score, color, label, reason = classify_host_key(alg)
            reference = lookup_nist_reference(alg)
            host_entries.append(
                AlgorithmEntry(alg, score, color, label, reason, reference)
            )
        host_entries.sort(key=lambda entry: entry.score)

        ciphers: List[CipherEntry] = []
        ciphers_cts = sorted(
            fields["encryption_algorithms_client_to_server"],
            key=cipher_sort_key,
        )
        for cipher in ciphers_cts:
            score, color, label, reason = classify_cipher(cipher)
            reference = lookup_nist_reference(cipher)
            ciphers.append(
                CipherEntry(
                    cipher,
                    "client->server",
                    score,
                    color,
                    label,
                    reason,
                    reference,
                )
            )

        ciphers_stc = sorted(
            fields["encryption_algorithms_server_to_client"],
            key=cipher_sort_key,
        )
        for cipher in ciphers_stc:
            score, color, label, reason = classify_cipher(cipher)
            reference = lookup_nist_reference(cipher)
            ciphers.append(
                CipherEntry(
                    cipher,
                    "server->client",
                    score,
                    color,
                    label,
                    reason,
                    reference,
                )
            )

        elapsed = time.perf_counter() - start_marker
        return ScanResult(
            host=host,
            port=port,
            banner=banner,
            version=version,
            supports_ssh2=True,
            resolved_hostname=resolved_hostname,
            kex_algorithms=kex_entries,
            host_key_algorithms=host_entries,
            ciphers=ciphers,
            macs_client_to_server=fields["mac_algorithms_client_to_server"],
            macs_server_to_client=fields["mac_algorithms_server_to_client"],
            first_kex_packet_follows=fields["first_kex_packet_follows"],
            cve_query=cve_query,
            cve_search_url=cve_search_url,
            cve_results=cve_results,
            duration_seconds=elapsed,
        )


def format_scan_result(result: ScanResult, use_color: bool) -> str:
    lines: List[str] = []
    lines.append(f"Remote banner: {result.banner}")
    lines.append(f"Version classification: {result.version}")
    if result.resolved_hostname:
        lines.append(f"Resolved hostname: {result.resolved_hostname}")
    else:
        lines.append("Resolved hostname: (reverse lookup unavailable)")

    if not result.supports_ssh2:
        lines.append("Server does not advertise SSH v2 support; stopping analysis.")
        return "\n".join(lines)

    lines.append("\nKey exchange algorithms (kex_algorithms):")
    for entry in result.kex_algorithms:
        color = entry.color if use_color else ""
        reset = Ansi.reset if use_color else ""
        name = f"{color}{entry.name}{reset}" if color else entry.name
        reference = f" [NIST: {entry.reference}]" if entry.reference else ""
        lines.append(f"  - {name} ({entry.label} - {entry.reason}{reference})")

    lines.append("\nHost key algorithms (server_host_key_algorithms):")
    for entry in result.host_key_algorithms:
        color = entry.color if use_color else ""
        reset = Ansi.reset if use_color else ""
        name = f"{color}{entry.name}{reset}" if color else entry.name
        reference = f" [NIST: {entry.reference}]" if entry.reference else ""
        lines.append(f"  - {name} ({entry.label} - {entry.reason}{reference})")

    for direction, heading in (
        ("client->server", "Offered ciphers (client->server):"),
        ("server->client", "Offered ciphers (server->client):"),
    ):
        lines.append(f"\n{heading}")
        for entry in (c for c in result.ciphers if c.direction == direction):
            color = entry.color if use_color else ""
            reset = Ansi.reset if use_color else ""
            name = f"{color}{entry.name}{reset}" if color else entry.name
            reference = f" [NIST: {entry.reference}]" if entry.reference else ""
            lines.append(f"  - {name} ({entry.label} - {entry.reason}{reference})")

    lines.append("\nProposed MACs (client->server):")
    for mac in result.macs_client_to_server:
        _, label = classify_mac(mac)
        lines.append(f"  - {mac} ({label})")

    lines.append("\nProposed MACs (server->client):")
    for mac in result.macs_server_to_client:
        _, label = classify_mac(mac)
        lines.append(f"  - {mac} ({label})")

    lines.append(f"\nfirst_kex_packet_follows: {result.first_kex_packet_follows}")

    if result.cve_query:
        lines.append(f"\nRelated CVEs for query '{result.cve_query}':")
        if result.cve_results:
            for entry in result.cve_results:
                summary = entry.get("summary", "").strip()
                summary_text = f" - {summary}" if summary else ""
                lines.append(f"  - {entry.get('id')}: {entry.get('url')}{summary_text}")
        else:
            fallback = result.cve_search_url or "https://nvd.nist.gov/vuln/search"
            lines.append(f"  - No CVEs retrieved. Search manually: {fallback}")

    return "\n".join(lines)


def sanitize_filename(host: str, port: int) -> str:
    safe_host = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in host)
    timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    return f"{safe_host}_{port}_{timestamp}"


def compute_strength_stats(result: ScanResult) -> Tuple[int, int, int, int]:
    strong = intermediate = weak = 0

    def consume(entries):
        nonlocal strong, intermediate, weak
        for entry in entries:
            if entry.label == "strong":
                strong += 1
            elif entry.label == "weak":
                weak += 1
            else:
                intermediate += 1

    consume(result.kex_algorithms)
    consume(result.host_key_algorithms)
    consume(result.ciphers)

    score = strong * 2 + intermediate - weak * 2
    if not result.supports_ssh2:
        score -= 5

    return score, strong, intermediate, weak


def result_to_plain_dict(result: ScanResult) -> dict:
    return {
        "host": result.host,
        "port": result.port,
        "banner": result.banner,
        "version": result.version,
        "supports_ssh2": result.supports_ssh2,
        "resolved_hostname": result.resolved_hostname,
        "first_kex_packet_follows": result.first_kex_packet_follows,
        "kex_algorithms": [
            {
                "name": entry.name,
                "strength": entry.label,
                "reason": entry.reason,
                "reference": entry.reference,
            }
            for entry in result.kex_algorithms
        ],
        "host_key_algorithms": [
            {
                "name": entry.name,
                "strength": entry.label,
                "reason": entry.reason,
                "reference": entry.reference,
            }
            for entry in result.host_key_algorithms
        ],
        "ciphers": [
            {
                "name": entry.name,
                "direction": entry.direction,
                "strength": entry.label,
                "reason": entry.reason,
                "reference": entry.reference,
            }
            for entry in result.ciphers
        ],
        "mac_algorithms": {
            "client_to_server": [
                {
                    "name": mac,
                    "strength": classify_mac(mac)[1],
                }
                for mac in result.macs_client_to_server
            ],
            "server_to_client": [
                {
                    "name": mac,
                    "strength": classify_mac(mac)[1],
                }
                for mac in result.macs_server_to_client
            ],
        },
        "cves": {
            "query": result.cve_query,
            "search_url": result.cve_search_url,
            "items": result.cve_results,
        },
        "duration_seconds": result.duration_seconds,
    }


def write_text_result(result: ScanResult, path: Path) -> None:
    content = format_scan_result(result, use_color=False)
    path.write_text(content + "\n", encoding="utf-8")


def write_csv_result(result: ScanResult, path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "host",
            "port",
            "section",
            "direction",
            "name",
            "strength",
            "reason",
            "reference",
        ])
        writer.writerow([result.host, result.port, "banner", "", result.banner, "", "", ""])
        writer.writerow([
            result.host,
            result.port,
            "resolved_hostname",
            "",
            result.resolved_hostname or "",
            "",
            "",
            "",
        ])
        writer.writerow([result.host, result.port, "version", "", result.version, "", "", ""])
        writer.writerow(
            [
                result.host,
                result.port,
                "first_kex_packet_follows",
                "",
                str(result.first_kex_packet_follows),
                "",
                "",
                "",
            ]
        )
        writer.writerow(
            [
                result.host,
                result.port,
                "scan_duration_seconds",
                "",
                f"{result.duration_seconds:.3f}",
                "",
                "",
                "",
            ]
        )

        for entry in result.kex_algorithms:
            writer.writerow(
                [
                    result.host,
                    result.port,
                    "kex_algorithm",
                    "",
                    entry.name,
                    entry.label,
                    entry.reason,
                    entry.reference or "",
                ]
            )

        for entry in result.host_key_algorithms:
            writer.writerow(
                [
                    result.host,
                    result.port,
                    "host_key_algorithm",
                    "",
                    entry.name,
                    entry.label,
                    entry.reason,
                    entry.reference or "",
                ]
            )

        for entry in result.ciphers:
            writer.writerow(
                [
                    result.host,
                    result.port,
                    "cipher",
                    entry.direction,
                    entry.name,
                    entry.label,
                    entry.reason,
                    entry.reference or "",
                ]
            )

        for mac in result.macs_client_to_server:
            _, label = classify_mac(mac)
            writer.writerow([result.host, result.port, "mac", "client->server", mac, label, "", ""])

        for mac in result.macs_server_to_client:
            _, label = classify_mac(mac)
            writer.writerow([result.host, result.port, "mac", "server->client", mac, label, "", ""])

        if result.cve_query:
            writer.writerow([
                result.host,
                result.port,
                "cve_query",
                "",
                result.cve_query,
                "",
                "",
                result.cve_search_url or "",
            ])
            for entry in result.cve_results:
                writer.writerow([
                    result.host,
                    result.port,
                    "cve",
                    "",
                    entry.get("id", ""),
                    "",
                    entry.get("summary", ""),
                    entry.get("url", ""),
                ])


def write_json_result(result: ScanResult, path: Path) -> None:
    payload = result_to_plain_dict(result)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def write_html_result(result: ScanResult, path: Path) -> None:
    payload = result_to_plain_dict(result)

    def color_for_label(label: str) -> str:
        return {
            "strong": "#2e7d32",
            "intermediate": "#f9a825",
            "weak": "#c62828",
        }.get(label, "#1976d2")

    lines: List[str] = []
    lines.append("<!DOCTYPE html>")
    lines.append("<html><head><meta charset=\"utf-8\"><title>SSH Scan Result</title>")
    lines.append(
        "<style>body{font-family:Menlo,Consolas,monospace;background:#0b0b0b;color:#e0e0e0;padding:16px;}"
        "h1{color:#64b5f6;} table{border-collapse:collapse;margin-top:12px;width:100%;}"
        "th,td{border:1px solid #444;padding:6px;text-align:left;}"
        "th{background:#1c1c1c;} .label{font-weight:bold;}</style>"
    )
    lines.append("</head><body>")
    lines.append(
        f"<h1>SSH Scan Result for {escape(result.host)}:{result.port}</h1>"
    )
    lines.append("<p class=\"label\">Banner:</p><pre>" + escape(result.banner) + "</pre>")
    lines.append(
        "<p class=\"label\">Version classification:</p><pre>"
        + escape(result.version)
        + "</pre>"
    )
    if result.resolved_hostname:
        lines.append(
            "<p class=\"label\">Resolved hostname:</p><pre>"
            + escape(result.resolved_hostname)
            + "</pre>"
        )
    else:
        lines.append(
            "<p class=\"label\">Resolved hostname:</p><pre>(reverse lookup unavailable)</pre>"
        )

    def build_table(title: str, rows: List[dict], include_direction: bool = False) -> None:
        lines.append(f"<h2>{escape(title)}</h2>")
        lines.append("<table><tr>")
        if include_direction:
            lines.append("<th>Direction</th>")
        lines.append("<th>Name</th><th>Strength</th><th>Reason</th></tr>")
        for row in rows:
            color = color_for_label(row["strength"])
            cell_parts: List[str] = []
            if include_direction:
                cell_parts.append(f"<td>{escape(row['direction'])}</td>")
            cell_parts.append(f"<td>{escape(row['name'])}</td>")
            cell_parts.append(f"<td style=\"color:{color}\">{escape(row['strength'])}</td>")
            cell_parts.append(f"<td>{escape(row['reason'])}</td>")
            lines.append("<tr>" + "".join(cell_parts) + "</tr>")
        lines.append("</table>")

    build_table("Key Exchange Algorithms", payload["kex_algorithms"])
    build_table("Host Key Algorithms", payload["host_key_algorithms"])
    build_table("Cipher Algorithms", payload["ciphers"], include_direction=True)

    lines.append("<h2>MAC Algorithms</h2>")
    mac_cts = payload["mac_algorithms"]["client_to_server"]
    mac_cts_lines = [f"{entry['name']} ({entry['strength']})" for entry in mac_cts]
    lines.append("<h3>Client to Server</h3><pre>" + escape("\n".join(mac_cts_lines)) + "</pre>")
    mac_stc = payload["mac_algorithms"]["server_to_client"]
    mac_stc_lines = [f"{entry['name']} ({entry['strength']})" for entry in mac_stc]
    lines.append("<h3>Server to Client</h3><pre>" + escape("\n".join(mac_stc_lines)) + "</pre>")
    lines.append(
        "<p>first_kex_packet_follows: "
        + escape(str(result.first_kex_packet_follows))
        + "</p>"
    )

    cve_payload = payload.get("cves", {})
    cve_query = cve_payload.get("query")
    if cve_query:
        lines.append("<h2>Related CVEs</h2>")
        if cve_payload.get("search_url"):
            link = escape(cve_payload["search_url"], quote=True)
            lines.append(
                f"<p>Search query: <strong>{escape(cve_query)}</strong> — <a href=\"{link}\" target=\"_blank\">View more on NVD</a></p>"
            )
        else:
            lines.append(f"<p>Search query: <strong>{escape(cve_query)}</strong></p>")

        items = cve_payload.get("items") or []
        if items:
            lines.append("<ul>")
            for entry in items:
                cve_id = escape(entry.get("id", ""))
                url = escape(entry.get("url", ""), quote=True)
                summary = escape(entry.get("summary", ""))
                link_html = f"<a href=\"{url}\" target=\"_blank\">{cve_id}</a>"
                details = f" — {summary}" if summary else ""
                lines.append(f"<li>{link_html}{details}</li>")
            lines.append("</ul>")
        else:
            fallback = cve_payload.get("search_url") or "https://nvd.nist.gov/vuln/search"
            link = escape(fallback, quote=True)
            lines.append(
                f"<p>No CVEs retrieved automatically. Try the <a href=\"{link}\" target=\"_blank\">NVD search results</a>.</p>"
            )

    lines.append("</body></html>")

    path.write_text("\n".join(lines), encoding="utf-8")


def write_ranking_html(
    results: List[ScanResult], path: Path, metadata: Optional[Dict[str, Any]] = None
) -> None:
    ranking = []
    cipher_counts: Dict[str, int] = {}
    cipher_strength: Dict[str, str] = {}
    algorithm_counts: Dict[str, int] = {}
    algorithm_strength: Dict[str, str] = {}
    key_size_counts: Dict[str, int] = {}
    key_size_score_sum: Dict[str, float] = {}
    key_size_algorithms: Dict[str, Set[str]] = {}
    cve_map: Dict[str, Dict[str, Any]] = {}

    for res in results:
        score, strong, intermediate, weak = compute_strength_stats(res)
        ranking.append(
            {
                "host": res.host,
                "port": res.port,
                "hostname": res.resolved_hostname,
                "duration_seconds": res.duration_seconds,
                "platform_insight": infer_platform_insight(res.banner),
                "score": score,
                "strong": strong,
                "intermediate": intermediate,
                "weak": weak,
                "supports_ssh2": res.supports_ssh2,
                "banner": res.banner,
                "version": res.version,
            }
        )

        for cipher_entry in res.ciphers:
            cipher_counts[cipher_entry.name] = cipher_counts.get(cipher_entry.name, 0) + 1
            stored_label = cipher_strength.get(cipher_entry.name, cipher_entry.label)
            if LABEL_PRIORITY.get(cipher_entry.label, 0) >= LABEL_PRIORITY.get(stored_label, 0):
                cipher_strength[cipher_entry.name] = cipher_entry.label

        for algo_entry in res.kex_algorithms:
            algorithm_counts[algo_entry.name] = algorithm_counts.get(algo_entry.name, 0) + 1
            stored_label = algorithm_strength.get(algo_entry.name, algo_entry.label)
            if LABEL_PRIORITY.get(algo_entry.label, 0) >= LABEL_PRIORITY.get(stored_label, 0):
                algorithm_strength[algo_entry.name] = algo_entry.label

        for host_entry in res.host_key_algorithms:
            key_size_label = extract_host_key_size(host_entry.name)
            key_size_counts[key_size_label] = key_size_counts.get(key_size_label, 0) + 1
            key_size_score_sum[key_size_label] = key_size_score_sum.get(key_size_label, 0.0) + LABEL_PRIORITY.get(host_entry.label, 0)
            key_size_algorithms.setdefault(key_size_label, set()).add(host_entry.name)

        for cve_entry in res.cve_results:
            cve_id = cve_entry.get("id")
            if not cve_id:
                continue
            bucket = cve_map.setdefault(
                cve_id,
                {
                    "id": cve_id,
                    "url": cve_entry.get("url"),
                    "summary": cve_entry.get("summary", ""),
                    "severity": (cve_entry.get("severity") or "").upper() or "UNKNOWN",
                    "score": cve_entry.get("score"),
                    "hosts": [],
                },
            )
            severity_value = (cve_entry.get("severity") or "").upper()
            if severity_value:
                current = bucket.get("severity", "UNKNOWN")
                if current == "UNKNOWN" or SEVERITY_ORDER.get(severity_value, 5) < SEVERITY_ORDER.get(current, 5):
                    bucket["severity"] = severity_value
            score_value = cve_entry.get("score")
            if isinstance(score_value, (int, float)):
                existing_score = bucket.get("score")
                if not isinstance(existing_score, (int, float)) or score_value > existing_score:
                    bucket["score"] = float(score_value)
            host_record = {
                "host": res.host,
                "port": res.port,
                "hostname": res.resolved_hostname,
            }
            if not any(
                existing["host"] == host_record["host"]
                and existing["port"] == host_record["port"]
                for existing in bucket["hosts"]
            ):
                bucket["hosts"].append(host_record)

    ranking.sort(key=lambda item: (item["score"], item["strong"], -item["weak"]), reverse=True)

    ranking_labels = [f"{entry['host']}:{entry['port']}" for entry in ranking]
    ranking_scores = [entry["score"] for entry in ranking]
    if ranking_scores:
        min_score = min(ranking_scores)
        max_score = max(ranking_scores)
        score_colors = [color_for_score(score, min_score, max_score) for score in ranking_scores]
    else:
        min_score = max_score = 0
        score_colors = []

    cipher_items = sorted(
        cipher_counts.items(),
        key=lambda pair: cipher_aggregate_sort_key(
            pair[0],
            pair[1],
            cipher_strength.get(pair[0], "intermediate"),
        ),
    )
    if cipher_items:
        cipher_labels = [name for name, _ in cipher_items]
        cipher_values = [count for _, count in cipher_items]
        cipher_colors = [LABEL_COLORS.get(cipher_strength.get(name, "intermediate"), "#ffd54f") for name in cipher_labels]
    else:
        cipher_labels = ["No data"]
        cipher_values = [0]
        cipher_colors = ["#757575"]

    algorithm_items = sorted(
        algorithm_counts.items(),
        key=lambda pair: algorithm_aggregate_sort_key(
            pair[0],
            pair[1],
            algorithm_strength.get(pair[0], "intermediate"),
        ),
    )
    if algorithm_items:
        algorithm_labels = [name for name, _ in algorithm_items]
        algorithm_values = [count for _, count in algorithm_items]
        algorithm_colors = [
            LABEL_COLORS.get(algorithm_strength.get(name, "intermediate"), "#ffd54f")
            for name in algorithm_labels
        ]
    else:
        algorithm_labels = ["No data"]
        algorithm_values = [0]
        algorithm_colors = ["#757575"]

    key_size_entries = []
    for label, count in key_size_counts.items():
        score_sum = key_size_score_sum.get(label, 0.0)
        strength_score = (score_sum / count) if count else 0.0
        algorithms = sorted(key_size_algorithms.get(label, set()))
        key_size_entries.append((label, count, strength_score, algorithms))

    key_size_entries.sort(key=lambda item: (-item[2], -item[1], item[0]))

    if key_size_entries:
        key_size_labels = [
            f"{label} ({', '.join(algs)})" if algs else label
            for label, _, _, algs in key_size_entries
        ]
        key_size_values = [count for _, count, _, _ in key_size_entries]
        key_size_colors = [color_for_score(score, 0.0, 2.0) for _, _, score, _ in key_size_entries]
    else:
        key_size_labels = ["No data"]
        key_size_values = [0]
        key_size_colors = ["#757575"]

    def cve_sort_key(entry: Dict[str, Any]) -> Tuple[int, int, float, str]:
        severity_token = (entry.get("severity") or "UNKNOWN").upper()
        severity_rank = SEVERITY_ORDER.get(severity_token, len(SEVERITY_ORDER))
        host_count = len(entry.get("hosts", []))
        score_value = entry.get("score")
        score_rank = -float(score_value) if isinstance(score_value, (int, float)) else 0.0
        return severity_rank, -host_count, score_rank, entry.get("id", "")

    cve_rows = sorted(
        (entry for entry in cve_map.values() if entry["hosts"]),
        key=cve_sort_key,
    )

    def render_bar_section(
        title: str,
        labels: List[str],
        values: List[int],
        default_color: str,
        colors: Optional[List[str]] = None,
    ) -> None:
        lines.append('<div class="chart-section">')
        lines.append(f"<h2>{escape(title)}</h2>")
        if not values or all(value == 0 for value in values):
            lines.append('<p>No data available.</p>')
            lines.append('</div>')
            return

        max_value = max(abs(value) for value in values)
        if max_value <= 0:
            lines.append('<p>No data available.</p>')
            lines.append('</div>')
            return

        for idx, (label, value) in enumerate(zip(labels, values)):
            percent = (abs(value) / max_value) * 100.0
            fill_color = colors[idx] if colors and idx < len(colors) else default_color
            lines.append('<div class="bar-row">')
            lines.append(
                f"<div class=\"bar-header\"><span class=\"bar-label\">{escape(label)}</span>"
                f"<span class=\"bar-value\">{value}</span></div>"
            )
            lines.append('<div class="bar-track">')
            lines.append(
                f"<div class=\"bar-fill\" style=\"width:{percent:.1f}%;background:{fill_color};\"></div>"
            )
            lines.append('</div>')
            lines.append('</div>')
        lines.append('</div>')

    lines: List[str] = []
    lines.append("<!DOCTYPE html>")
    lines.append("<html><head><meta charset=\"utf-8\"><title>SSH Scan Ranking</title>")
    lines.append(
        "<style>body{font-family:Menlo,Consolas,monospace;background:#111;color:#eaeaea;padding:18px;}"
        "h1{color:#90caf9;} table{border-collapse:collapse;width:100%;margin-top:16px;}"
        "th,td{border:1px solid #444;padding:6px;text-align:left;}"
        "th{background:#1f1f1f;} .weak{color:#ef5350;} .strong{color:#66bb6a;} .intermediate{color:#ffca28;}"
        ".run-metadata{background:#1b1b1b;border:1px solid #333;padding:12px;border-radius:8px;margin-top:18px;}"
        ".run-metadata h2{margin-top:0;color:#90caf9;font-size:1.2rem;}"
        ".run-metadata ul{list-style:none;padding-left:0;margin:8px 0 0;}"
        ".run-metadata li{margin:4px 0;}"
        ".meta-label{font-weight:bold;color:#e0e0e0;margin-right:6px;}"
        ".meta-code{background:#212121;padding:2px 6px;border-radius:4px;}"
        ".chart-stack{display:flex;flex-direction:column;gap:18px;margin-top:18px;}"
        ".chart-section{background:#1b1b1b;border:1px solid #333;padding:12px;border-radius:8px;}"
        ".bar-row{margin-top:12px;}"
        ".bar-header{display:flex;justify-content:space-between;font-size:0.95rem;}"
        ".bar-label{color:#e0e0e0;max-width:70%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}"
        ".bar-value{color:#64b5f6;margin-left:12px;}"
        ".bar-track{background:#2a2a2a;border-radius:6px;height:10px;margin-top:4px;overflow:hidden;}"
        ".bar-fill{height:100%;border-radius:6px;}"
        ".bar-fill-negative{background:#ef5350;}"
        ".cve-host-groups{margin-top:28px;}"
        ".cve-host-groups table{margin-top:12px;}"
        ".cve-host-list{margin:8px 0 0 18px;}"
        ".cve-host{color:#e0e0e0;}"
        ".cve-hostname{color:#90caf9;}"
        ".cve-severity{display:block;font-weight:bold;}"
        ".cve-score{display:block;font-size:0.85rem;color:#fdd835;margin-top:2px;}"
        ".severity-critical{color:#ef5350;}"
        ".severity-high{color:#ff7043;}"
        ".severity-medium{color:#ffca28;}"
        ".severity-low{color:#64b5f6;}"
        ".severity-none{color:#90caf9;}"
        ".severity-unknown{color:#b0bec5;}"
        "</style>"
    )
    lines.append("</head><body>")
    lines.append("<h1>Parallel SSH Scan Ranking</h1>")
    if metadata:
        command_text = metadata.get("command") if isinstance(metadata, dict) else None
        start_value = metadata.get("start_time") if isinstance(metadata, dict) else None
        end_value = metadata.get("end_time") if isinstance(metadata, dict) else None
        average_value = metadata.get("average_seconds") if isinstance(metadata, dict) else None
        total_value = metadata.get("total_duration_seconds") if isinstance(metadata, dict) else None
        host_count = metadata.get("host_count") if isinstance(metadata, dict) else None

        if isinstance(start_value, datetime):
            start_text = start_value.strftime("%Y-%m-%d %H:%M:%S")
        else:
            start_text = str(start_value) if start_value else ""

        if isinstance(end_value, datetime):
            end_text = end_value.strftime("%Y-%m-%d %H:%M:%S")
        else:
            end_text = str(end_value) if end_value else ""

        if isinstance(average_value, (int, float)):
            average_text = f"{average_value:.3f} s"
        else:
            average_text = str(average_value) if average_value else ""

        if isinstance(total_value, (int, float)):
            total_text = f"{total_value:.3f} s"
        else:
            total_text = str(total_value) if total_value else ""

        host_text = str(host_count) if host_count is not None else ""

        lines.append('<div class="run-metadata">')
        lines.append("<h2>Execution Summary</h2>")
        lines.append("<ul>")
        if command_text:
            lines.append(
                f"<li><span class=\"meta-label\">Command:</span><code class=\"meta-code\">{escape(str(command_text))}</code></li>"
            )
        if start_text:
            lines.append(
                f"<li><span class=\"meta-label\">Start:</span>{escape(start_text)}</li>"
            )
        if end_text:
            lines.append(
                f"<li><span class=\"meta-label\">End:</span>{escape(end_text)}</li>"
            )
        if total_text:
            lines.append(
                f"<li><span class=\"meta-label\">Total Runtime:</span>{escape(total_text)}</li>"
            )
        if average_text:
            lines.append(
                f"<li><span class=\"meta-label\">Average Per Host:</span>{escape(average_text)}</li>"
            )
        if host_text:
            lines.append(
                f"<li><span class=\"meta-label\">Hosts Analyzed:</span>{escape(host_text)}</li>"
            )
        lines.append("</ul>")
        lines.append("</div>")
    lines.append(
        "<p>The ranking score applies 2 points for each strong finding, 1 point for"
        " each intermediate finding, and subtracts 2 points for each weak finding;"
        " hosts that do not support SSH v2 incur an additional 5 point penalty.</p>"
    )
    lines.append("<table><tr><th>Rank</th><th>Host</th><th>Hostname</th><th>Duration (s)</th><th>Platform Insight</th><th>Score</th><th>Strong</th><th>Intermediate</th><th>Weak</th><th>SSH v2</th><th>Banner</th></tr>")

    for idx, entry in enumerate(ranking, start=1):
        supports = "yes" if entry["supports_ssh2"] else "no"
        score_class = "strong" if entry["score"] > 0 else ("weak" if entry["score"] < 0 else "intermediate")
        lines.append("<tr>")
        lines.append(f"<td>{idx}</td>")
        lines.append(f"<td>{escape(entry['host'])}:{entry['port']}</td>")
        hostname = entry.get("hostname") or "n/a"
        lines.append(f"<td>{escape(hostname)}</td>")
        duration_value = entry.get("duration_seconds", 0.0)
        lines.append(f"<td>{duration_value:.3f}</td>")
        platform_value = entry.get("platform_insight") or "Unknown"
        lines.append(f"<td>{escape(platform_value)}</td>")
        lines.append(
            f"<td class=\"{score_class}\">{entry['score']}</td><td>{entry['strong']}</td>"
            f"<td>{entry['intermediate']}</td><td class=\"weak\">{entry['weak']}</td><td>{supports}</td>"
        )
        lines.append(f"<td>{escape(entry['banner'])}</td>")
        lines.append("</tr>")

    lines.append("</table>")
    lines.append('<div class="chart-stack">')
    render_bar_section("Score Ranking", ranking_labels, ranking_scores, "#64b5f6", score_colors)
    render_bar_section("Cipher Occurrences", cipher_labels, cipher_values, "#ffd54f", cipher_colors)
    render_bar_section("Algorithm Occurrences", algorithm_labels, algorithm_values, "#81c784", algorithm_colors)
    render_bar_section("Key Size Occurrences", key_size_labels, key_size_values, "#ba68c8", key_size_colors)
    lines.append('</div>')
    if cve_rows:
        lines.append('<div class="cve-host-groups">')
        lines.append("<h2>Hosts Sharing Common CVEs</h2>")
        lines.append("<table><tr><th>Rank</th><th>CVE</th><th>Severity</th><th>Affected Hosts</th><th>Summary</th></tr>")
        for idx, entry in enumerate(cve_rows, start=1):
            hosts = entry["hosts"]
            host_items = []
            for host_info in hosts:
                host_label = f"{host_info['host']}:{host_info['port']}"
                hostname = host_info.get("hostname") or "n/a"
                host_items.append(
                    f"<li><span class=\"cve-host\">{escape(host_label)}</span> "
                    f"<span class=\"cve-hostname\">({escape(hostname)})</span></li>"
                )
            hosts_html = '<ul class="cve-host-list">' + "".join(host_items) + "</ul>"
            severity_token = (entry.get("severity") or "UNKNOWN").upper()
            severity_label = severity_token.title() if severity_token != "UNKNOWN" else "Unknown"
            severity_class = f"severity-{severity_token.lower()}"
            severity_cell = f"<span class=\"cve-severity {severity_class}\">{escape(severity_label)}</span>"
            score_value = entry.get("score")
            if isinstance(score_value, (int, float)):
                severity_cell += f"<span class=\"cve-score\">Score: {score_value:.1f}</span>"
            if entry.get("url"):
                cve_link = escape(entry["url"], quote=True)
                cve_cell = f"<a href=\"{cve_link}\" target=\"_blank\">{escape(entry['id'])}</a>"
            else:
                cve_cell = escape(entry["id"])
            summary_text = escape(entry.get("summary", ""))
            lines.append("<tr>")
            lines.append(f"<td>{idx}</td>")
            lines.append(f"<td>{cve_cell}</td>")
            lines.append(f"<td>{severity_cell}</td>")
            lines.append(f"<td>{len(hosts)} host(s){hosts_html}</td>")
            lines.append(f"<td>{summary_text}</td>")
            lines.append("</tr>")
        lines.append("</table>")
        lines.append("</div>")
    lines.append("</body></html>")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    global LOG_FILE_HANDLE
    ensure_environment_ready()

    parser = argparse.ArgumentParser(
        description="Simple SSH banner scanner that lists algorithms/ciphers from KEXINIT.",
        epilog=(
            "Tip: For unattended runs, invoke this script via job runners such as 'nohup python ssh-scanner.py … &' on "
            "Unix-like systems or 'Start-Job { python ssh-scanner.py … }' in PowerShell so the scan continues after "
            "you disconnect."
        ),
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Host/IP or CIDR to probe. Append :port or use [IPv6]:port for per-target overrides.",
    )
    parser.add_argument("-p", "--port", type=int, default=22, help="SSH port (default: 22).")
    parser.add_argument(
        "-t", "--timeout", type=float, default=5.0, help="Connection/IO timeout in seconds (default: 5.0)."
    )
    parser.add_argument(
        "-r",
        "--range",
        help="Additional CIDR range to scan (optionally with :port), e.g. 192.168.0.0/28:2222.",
    )
    parser.add_argument(
        "-f",
        "--file",
        help=".conf file listing hosts or CIDR ranges (optionally :port or [IPv6]:port), one per line.",
    )
    parser.add_argument(
        "--parallel-workers",
        type=int,
        default=1,
        help="Number of worker threads. Values >1 enable parallel execution with per-target output files.",
    )
    parser.add_argument(
        "--parallel-output-format",
        choices=("text", "csv"),
        default="text",
        help="Deprecated; parallel mode now writes text, JSON, HTML, and CSV for each target.",
    )
    parser.add_argument(
        "--parallel-output-dir",
        default="ssh_scan_results",
        help="Directory to store per-target outputs when parallel execution is enabled.",
    )
    random_group = parser.add_mutually_exclusive_group()
    random_group.add_argument(
        "--random",
        dest="randomize_order",
        action="store_true",
        help="Shuffle the target list before scanning (default).",
    )
    random_group.add_argument(
        "--no-random",
        dest="randomize_order",
        action="store_false",
        help="Disable target randomization and scan sequentially.",
    )
    parser.set_defaults(randomize_order=True)
    parser.add_argument(
        "--lookup-cves",
        action="store_true",
        help="Attempt to retrieve related CVEs from NVD based on the SSH banner (requires internet).",
    )
    parser.add_argument(
        "--max-cve-results",
        type=int,
        default=10,
        help="Maximum number of CVE records to include when --lookup-cves is enabled (default: 10).",
    )

    args = parser.parse_args()

    try:
        if args.port <= 0 or args.port > 65535:
            log_message("--port must be between 1 and 65535.", error=True)
            sys.exit(1)

        use_color = sys.stdout.isatty()
        if not use_color:
            Ansi.disable()
        try:
            targets = collect_targets(args, args.port)
        except ValueError as exc:
            log_message(str(exc), error=True)
            sys.exit(1)

        if not targets:
            log_message("No targets provided.", error=True)
            sys.exit(1)

        if args.parallel_workers < 1:
            log_message("--parallel-workers must be >= 1.", error=True)
            sys.exit(1)

        overall_start = datetime.now()
        command_parts = sys.argv[:] if sys.argv else ["ssh-scanner.py"]
        if command_parts:
            command_parts[0] = Path(command_parts[0]).name
        formatted_command = " ".join(command_parts)
        run_suffix = overall_start.strftime("%Y_%m_%d_%H_%M_%S")

        if args.parallel_workers == 1:
            output_dir = Path(args.parallel_output_dir) / run_suffix
            output_dir.mkdir(parents=True, exist_ok=True)
            log_path = initialize_run_log(output_dir, overall_start)
            log_message(f"Execution log will be saved to {log_path.name}")
            collected_results: List[ScanResult] = []
            progress = ProgressIndicator(total=len(targets))
            progress.start()

            try:
                for host, port in targets:
                    progress.task_started()
                    log_message(f"\n===== {host}:{port} =====")
                    host_start = datetime.now()
                    log_message(
                        f"Scan started at {host_start.isoformat(timespec='seconds')} for {host}:{port}"
                    )
                    scan_failed = False
                    try:
                        result = scan_target(
                            host,
                            port,
                            args.timeout,
                            lookup_cves=args.lookup_cves,
                            max_cves=max(0, args.max_cve_results),
                            resolve_hostname=True,
                        )
                    except (socket.error, RuntimeError) as exc:
                        log_message(f"Failed to probe {host}:{port} -> {exc}", error=True)
                        scan_failed = True
                    else:
                        collected_results.append(result)
                        log_message(format_scan_result(result, use_color=use_color))

                        base_name = sanitize_filename(host, port)
                        text_path = output_dir / f"{base_name}.txt"
                        json_path = output_dir / f"{base_name}.json"
                        html_path = output_dir / f"{base_name}.html"
                        csv_path = output_dir / f"{base_name}.csv"

                        write_text_result(result, text_path)
                        write_json_result(result, json_path)
                        write_html_result(result, html_path)
                        write_csv_result(result, csv_path)

                        log_message(
                            "Saved results for {host}:{port} -> {txt}, {js}, {ht}, {csv}".format(
                                host=host,
                                port=port,
                                txt=text_path.name,
                                js=json_path.name,
                                ht=html_path.name,
                                csv=csv_path.name,
                            )
                        )
                    finally:
                        host_end = datetime.now()
                        duration = (host_end - host_start).total_seconds()
                        status = "FAILED" if scan_failed else "completed"
                        log_message(
                            f"Scan finished at {host_end.isoformat(timespec='seconds')} for {host}:{port}"
                            f" (status: {status}, duration: {duration:.2f}s)"
                        )
                        progress.task_finished()
            finally:
                progress.stop()

            if collected_results:
                overall_end = datetime.now()
                total_duration_seconds = sum(result.duration_seconds for result in collected_results)
                average_duration_seconds = (
                    total_duration_seconds / len(collected_results) if collected_results else 0.0
                )
                run_metadata = {
                    "command": formatted_command,
                    "start_time": overall_start.strftime("%Y-%m-%d %H:%M:%S"),
                    "end_time": overall_end.strftime("%Y-%m-%d %H:%M:%S"),
                    "total_duration_seconds": (overall_end - overall_start).total_seconds(),
                    "average_seconds": average_duration_seconds,
                    "host_count": len(collected_results),
                }
                suffix = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
                ranking_path = output_dir / f"summary_ranking_{suffix}.html"
                write_ranking_html(collected_results, ranking_path, run_metadata)
                log_message(f"Wrote ranking summary to {ranking_path.name}")
        else:
            output_dir = Path(args.parallel_output_dir) / run_suffix
            output_dir.mkdir(parents=True, exist_ok=True)
            log_path = initialize_run_log(output_dir, overall_start)
            log_message(
                f"Parallel execution enabled with {args.parallel_workers} workers; writing outputs to {output_dir.resolve()}"
            )
            log_message(f"Execution log will be saved to {log_path.name}")

            progress = ProgressIndicator(total=len(targets))
            progress.start()

            def task(target_host: str, target_port: int) -> ScanResult:
                progress.task_started()
                task_start = datetime.now()
                log_message(
                    f"Scan started at {task_start.isoformat(timespec='seconds')} for {target_host}:{target_port}"
                )
                succeeded = False
                try:
                    result = scan_target(
                        target_host,
                        target_port,
                        args.timeout,
                        lookup_cves=args.lookup_cves,
                        max_cves=max(0, args.max_cve_results),
                        resolve_hostname=True,
                    )
                    succeeded = True
                    return result
                finally:
                    task_end = datetime.now()
                    duration = (task_end - task_start).total_seconds()
                    status = "FAILED" if not succeeded else "completed"
                    log_message(
                        f"Scan finished at {task_end.isoformat(timespec='seconds')} for {target_host}:{target_port}"
                        f" (status: {status}, duration: {duration:.2f}s)"
                    )
                    progress.task_finished()

            collected_results: List[ScanResult] = []

            try:
                with ThreadPoolExecutor(max_workers=args.parallel_workers) as executor:
                    futures = {
                        executor.submit(task, host, port): (host, port)
                        for host, port in targets
                    }

                    for future in as_completed(futures):
                        host, port = futures[future]
                        try:
                            result = future.result()
                        except (socket.error, RuntimeError) as exc:
                            log_message(f"Failed to probe {host}:{port} -> {exc}", error=True)
                            continue

                        collected_results.append(result)
                        base_name = sanitize_filename(host, port)
                        text_path = output_dir / f"{base_name}.txt"
                        json_path = output_dir / f"{base_name}.json"
                        html_path = output_dir / f"{base_name}.html"
                        csv_path = output_dir / f"{base_name}.csv"

                        write_text_result(result, text_path)
                        write_json_result(result, json_path)
                        write_html_result(result, html_path)
                        write_csv_result(result, csv_path)

                        log_message(
                            "Saved results for {host}:{port} -> {txt}, {js}, {ht}, {csv}".format(
                                host=host,
                                port=port,
                                txt=text_path.name,
                                js=json_path.name,
                                ht=html_path.name,
                                csv=csv_path.name,
                            )
                        )
            finally:
                progress.stop()

            if collected_results:
                overall_end = datetime.now()
                total_duration_seconds = sum(result.duration_seconds for result in collected_results)
                average_duration_seconds = (
                    total_duration_seconds / len(collected_results) if collected_results else 0.0
                )
                run_metadata = {
                    "command": formatted_command,
                    "start_time": overall_start.strftime("%Y-%m-%d %H:%M:%S"),
                    "end_time": overall_end.strftime("%Y-%m-%d %H:%M:%S"),
                    "total_duration_seconds": (overall_end - overall_start).total_seconds(),
                    "average_seconds": average_duration_seconds,
                    "host_count": len(collected_results),
                }
                suffix = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
                ranking_path = output_dir / f"summary_ranking_{suffix}.html"
                write_ranking_html(collected_results, ranking_path, run_metadata)
                log_message(f"Wrote ranking summary to {ranking_path.name}")
    finally:
        if LOG_FILE_HANDLE:
            LOG_FILE_HANDLE.close()
            LOG_FILE_HANDLE = None


if __name__ == "__main__":
    main()