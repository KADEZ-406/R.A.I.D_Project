import json
from pathlib import Path


_SIG_PATH = Path(__file__).with_name("signatures.json")

with open(_SIG_PATH, "r", encoding="utf-8") as f:
    _RAW = json.load(f)

signatures = {
    "sql_errors": _RAW.get("sql_errors", []),
    "generic_errors": _RAW.get("generic_errors", []),
    "database_errors": _RAW.get("database_errors", []),
    "xss_indicators": _RAW.get("xss_indicators", []),
    "file_inclusion_errors": _RAW.get("file_inclusion_errors", []),
    "command_injection_indicators": _RAW.get("command_injection_indicators", []),
    "debug_information": _RAW.get("debug_information", []),
}


