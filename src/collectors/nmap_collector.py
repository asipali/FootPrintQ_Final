"""
OSINT-RECON Nmap Active Reconnaissance Collector Module
Executes Nmap safely using subprocess argument lists with explicit timeouts,
evidence preservation, SHA256 checksum generation, and error boundary isolation.
"""

import os
import re
import shutil
import hashlib
import subprocess
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple

from src.schema import TargetAuthorizationRecord

# Supported controlled lab scanning profiles
SUPPORTED_PROFILES: Dict[str, Dict[str, Any]] = {
    "lab-basic": {
        "description": "Standard controlled TCP Connect scan with service/version detection (Top 100 ports).",
        "args": ["-sT", "-sV", "-Pn", "--top-ports", "100"]
    },
    "lab-safe-minimal": {
        "description": "Fast minimal TCP Connect scan covering top 10 standard infrastructure ports.",
        "args": ["-sT", "-sV", "-Pn", "-p", "21,22,23,25,80,443,445,3306,5432,8080"]
    },
    "lab-common-services": {
        "description": "Controlled scan covering known Metasploitable2 lab services without intrusive scripts.",
        "args": [
            "-sT", "-sV", "-Pn", "-p",
            "21,22,23,25,53,80,110,111,139,143,445,512,513,514,1099,1524,2049,2121,3306,3632,5432,5900,6000,6667,8009,8180"
        ]
    }
}


def compute_file_sha256(filepath: str) -> str:
    """Computes SHA256 hash of a file for integrity verification."""
    if not os.path.exists(filepath):
        return ""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


class NmapCollectorResult:
    """Container for low-level Nmap execution outputs and evidence paths."""

    def __init__(
        self,
        command_list: List[str],
        returncode: int,
        stdout: str,
        stderr: str,
        xml_path: Optional[str] = None,
        stdout_path: Optional[str] = None,
        stderr_path: Optional[str] = None,
        metadata_path: Optional[str] = None,
        duration_seconds: float = 0.0,
        file_hashes: Optional[Dict[str, str]] = None,
        error_message: Optional[str] = None
    ):
        self.command_list = command_list
        self.command_str = " ".join(command_list)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.xml_path = xml_path
        self.stdout_path = stdout_path
        self.stderr_path = stderr_path
        self.metadata_path = metadata_path
        self.duration_seconds = duration_seconds
        self.file_hashes = file_hashes or {}
        self.error_message = error_message


def resolve_nmap_binary(specified_path: Optional[str] = None) -> str:
    """Cross-platform binary resolution for Nmap across Linux and Windows."""
    if specified_path and os.path.exists(specified_path):
        return specified_path

    env_path = os.getenv("NMAP_PATH")
    if env_path and os.path.exists(env_path):
        return env_path

    which_path = shutil.which("nmap") or shutil.which("nmap.exe")
    if which_path:
        return which_path

    if os.name == "nt":
        for win_path in [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe"
        ]:
            if os.path.isfile(win_path):
                return win_path

    if os.path.exists("/usr/bin/nmap"):
        return "/usr/bin/nmap"

    return "nmap"


class NmapCollector:
    """
    Executes controlled active Nmap reconnaissance with strict argument list isolation.
    """

    def __init__(
        self,
        binary_path: Optional[str] = None,
        timeout: int = 60
    ):
        self.binary_path = resolve_nmap_binary(binary_path)
        self.timeout = timeout
        self.version = self._detect_version()

    def _detect_version(self) -> str:
        """Dynamically detects installed Nmap version via subprocess."""
        if os.path.exists(self.binary_path):
            try:
                proc = subprocess.run(
                    [self.binary_path, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                output = proc.stdout or proc.stderr or ""
                match = re.search(r"Nmap\s+version\s+([\d\.]+)", output, re.IGNORECASE)
                if match:
                    return match.group(1)
            except Exception:
                pass
        return "7.99"

    def execute_scan(
        self,
        auth_record: TargetAuthorizationRecord,
        profile_name: str = "lab-basic",
        output_dir: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> NmapCollectorResult:
        """
        Executes Nmap scan using safe argument lists and preserves raw XML and logs.
        """
        if not os.path.exists(self.binary_path):
            raise FileNotFoundError(f"Nmap binary not found at: '{self.binary_path}'")

        if profile_name not in SUPPORTED_PROFILES:
            raise ValueError(
                f"Unsupported scan profile '{profile_name}'. "
                f"Supported profiles: {list(SUPPORTED_PROFILES.keys())}"
            )

        target = auth_record.target
        effective_timeout = timeout or self.timeout

        # Output paths
        xml_path = None
        stdout_path = None
        stderr_path = None
        metadata_path = None

        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            xml_path = os.path.join(output_dir, "nmap_scan.xml")
            stdout_path = os.path.join(output_dir, "nmap_stdout.txt")
            stderr_path = os.path.join(output_dir, "nmap_stderr.txt")
            metadata_path = os.path.join(output_dir, "scan_metadata.json")

        profile_args = SUPPORTED_PROFILES[profile_name]["args"]

        # Build argument list strictly without shell=True
        cmd = [self.binary_path] + list(profile_args)
        if xml_path:
            cmd.extend(["-oX", xml_path])
        cmd.append(target)

        start_time = datetime.now(timezone.utc)
        returncode = -1
        stdout = ""
        stderr = ""
        error_message = None

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=effective_timeout
            )
            returncode = proc.returncode
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""

            if returncode != 0:
                error_message = f"Nmap exited with non-zero code {returncode}: {stderr.strip() or stdout.strip()}"
        except subprocess.TimeoutExpired:
            returncode = -1
            error_message = f"Nmap execution timed out after {effective_timeout} seconds"
            stderr = error_message
        except Exception as e:
            returncode = -2
            error_message = f"Nmap execution failed: {str(e)}"
            stderr = error_message

        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()

        # Save standard streams if output directory was configured
        file_hashes: Dict[str, str] = {}
        if output_dir:
            if stdout_path:
                try:
                    with open(stdout_path, "w", encoding="utf-8") as f:
                        f.write(stdout)
                    file_hashes["stdout"] = compute_file_sha256(stdout_path)
                except IOError as ioe:
                    stderr += f"\nFailed to write stdout file: {ioe}"

            if stderr_path:
                try:
                    with open(stderr_path, "w", encoding="utf-8") as f:
                        f.write(stderr)
                    file_hashes["stderr"] = compute_file_sha256(stderr_path)
                except IOError as ioe:
                    pass

            if xml_path and os.path.exists(xml_path):
                file_hashes["xml"] = compute_file_sha256(xml_path)

        return NmapCollectorResult(
            command_list=cmd,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            xml_path=xml_path,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            metadata_path=metadata_path,
            duration_seconds=duration,
            file_hashes=file_hashes,
            error_message=error_message
        )

