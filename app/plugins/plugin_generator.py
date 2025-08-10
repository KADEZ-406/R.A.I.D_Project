"""
Plugin generator for R.A.I.D

Generates plugin stubs from checks manifest with a standardized METADATA and
async run() signature.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict

TEMPLATE = """"""
"""

PLUGIN_STUB = """
"""


def _make_stub(module_name: str, meta: Dict) -> str:
    return f""""""
"""


def generate_plugin_template(name: str, category: str, mode: str) -> str:
    """Create a minimal plugin stub under app/plugins.

    The stub includes METADATA and a no-op run() that returns an empty list.
    """
    safe_name = name.strip().lower().replace(" ", "_")
    plugin_path = Path("app/plugins") / f"{safe_name}.py"
    if plugin_path.exists():
        return str(plugin_path)

    content = f'''"""
Auto-generated plugin stub for {name}
"""

from typing import List

from app.core.model import Finding


METADATA = {{
    "id": "{safe_name}",
    "name": "{name}",
    "category": "{category}",
    "severity_hint": "Low",
    "required_mode": "{mode}",
    "implemented": False,
}}


async def run(target: str, http, ctx) -> list[Finding]:
    return []
'''

    plugin_path.write_text(content, encoding="utf-8")
    return str(plugin_path)


