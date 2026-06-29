"""
core/version_config.py  — NEW FILE

Authoritative Mule Runtime → MUnit version compatibility matrix.
Import this in app.py to power the runtime/version dropdown API.

Usage:
    from core.version_config import RUNTIME_VERSIONS, get_munit_versions_for_runtime,
                                     get_recommended_munit_version, get_plugin_version
"""

from typing import Dict, List, Optional

# ─────────────────────────────────────────────────────────────────────────────
# Supported runtime versions (shown in the UI dropdown)
# ─────────────────────────────────────────────────────────────────────────────
RUNTIME_VERSIONS: List[str] = [
    "4.1", "4.2", "4.3", "4.4", "4.5", "4.6", "4.7", "4.8", "4.9",
]

# ─────────────────────────────────────────────────────────────────────────────
# MUnit 2.x: compatible with Mule 4.1 – 4.4
# MUnit 3.x: requires Mule 4.5+
#
# Sources: MuleSoft release notes for MUnit 2.x and 3.x; Anypoint Platform
#          compatibility matrix (2024).
# ─────────────────────────────────────────────────────────────────────────────
_RUNTIME_MUNIT_MAP: Dict[str, Dict] = {
    "4.1": {
        "series": "2.x",
        "versions": ["2.1.0", "2.1.1", "2.1.2", "2.1.3", "2.1.4", "2.1.5"],
        "recommended": "2.1.5",
        "plugin": "2.1.5",
    },
    "4.2": {
        "series": "2.x",
        "versions": ["2.2.0", "2.2.1", "2.2.2", "2.2.3", "2.2.4", "2.2.5"],
        "recommended": "2.2.5",
        "plugin": "2.2.5",
    },
    "4.3": {
        "series": "2.x",
        # MUnit 3.x is NOT compatible with Mule 4.3. The correct series is 2.3.x.
        "versions": [
            "2.3.0", "2.3.1", "2.3.2", "2.3.3", "2.3.4", "2.3.5",
            "2.3.6", "2.3.7", "2.3.8", "2.3.9", "2.3.10", "2.3.11",
            "2.3.12", "2.3.13", "2.3.14", "2.3.15",
        ],
        "recommended": "2.3.15",
        "plugin": "2.3.15",
    },
    "4.4": {
        "series": "2.x",
        # MUnit 3.x is NOT compatible with Mule 4.4. Must use 2.3.x.
        "versions": [
            "2.3.4", "2.3.5", "2.3.6", "2.3.7", "2.3.8", "2.3.9",
            "2.3.10", "2.3.11", "2.3.12", "2.3.13", "2.3.14", "2.3.15",
        ],
        "recommended": "2.3.15",
        "plugin": "2.3.15",
    },
    "4.5": {
        "series": "3.x",
        "versions": ["3.0.0", "3.0.1", "3.0.2", "3.0.3", "3.1.0", "3.2.0", "3.3.0"],
        "recommended": "3.3.0",
        "plugin": "3.3.0",
    },
    "4.6": {
        "series": "3.x",
        "versions": ["3.2.0", "3.3.0", "3.4.0", "3.5.0", "3.6.0"],
        "recommended": "3.6.0",
        "plugin": "3.6.0",
    },
    "4.7": {
        "series": "3.x",
        "versions": ["3.4.0", "3.5.0", "3.6.0"],
        "recommended": "3.6.0",
        "plugin": "3.6.0",
    },
    "4.8": {
        "series": "3.x",
        "versions": ["3.5.0", "3.6.0"],
        "recommended": "3.6.0",
        "plugin": "3.6.0",
    },
    "4.9": {
        "series": "3.x",
        "versions": ["3.6.0"],
        "recommended": "3.6.0",
        "plugin": "3.6.0",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def get_munit_versions_for_runtime(runtime_version: str) -> List[str]:
    """Return the list of compatible MUnit versions for a Mule runtime version."""
    entry = _RUNTIME_MUNIT_MAP.get(runtime_version)
    if not entry:
        # Closest fallback: strip micro if user passed e.g. "4.4.0"
        major_minor = ".".join(runtime_version.split(".")[:2])
        entry = _RUNTIME_MUNIT_MAP.get(major_minor)
    return (entry or {}).get("versions", [])


def get_recommended_munit_version(runtime_version: str) -> Optional[str]:
    """Return the recommended (latest stable) MUnit version for a runtime."""
    entry = _RUNTIME_MUNIT_MAP.get(runtime_version)
    if not entry:
        major_minor = ".".join(runtime_version.split(".")[:2])
        entry = _RUNTIME_MUNIT_MAP.get(major_minor)
    return (entry or {}).get("recommended")


def get_plugin_version(munit_version: str) -> str:
    """
    Return the munit-maven-plugin version for a given MUnit version.
    Plugin major version tracks MUnit major version.
    """
    major = int(munit_version.split(".")[0])
    if major >= 3:
        # All 3.x plugin versions — use the same version string as MUnit
        return munit_version
    # 2.x: plugin version = munit version
    return munit_version


def get_munit_series(runtime_version: str) -> str:
    """Return '2.x' or '3.x' for the given Mule runtime version."""
    major_minor = ".".join(runtime_version.split(".")[:2])
    return _RUNTIME_MUNIT_MAP.get(major_minor, {}).get("series", "2.x")


def get_pom_snippet(munit_version: str, runtime_version: str = "") -> str:
    """
    Generate the POM XML snippet needed to add MUnit support.
    """
    plugin_version = get_plugin_version(munit_version)
    # Get mule.version property value for <appRef> if needed
    mule_prop = f"<mule.version>{runtime_version}</mule.version>" if runtime_version else ""

    return f"""<!-- ─── MUnit dependencies (add to <dependencies>) ─────────────────── -->
<dependency>
    <groupId>com.mulesoft.munit</groupId>
    <artifactId>munit-runner</artifactId>
    <version>{munit_version}</version>
    <classifier>mule-plugin</classifier>
    <scope>test</scope>
</dependency>
<dependency>
    <groupId>com.mulesoft.munit</groupId>
    <artifactId>munit-tools</artifactId>
    <version>{munit_version}</version>
    <classifier>mule-plugin</classifier>
    <scope>test</scope>
</dependency>

<!-- ─── MUnit maven plugin (add to <build><plugins>) ───────────────── -->
<plugin>
    <groupId>com.mulesoft.munit.tools</groupId>
    <artifactId>munit-maven-plugin</artifactId>
    <version>{plugin_version}</version>
    <executions>
        <execution>
            <id>test</id>
            <phase>test</phase>
            <goals>
                <goal>test</goal>
                <goal>coverage-report</goal>
            </goals>
        </execution>
    </executions>
    <configuration>
        <coverage>
            <runCoverage>true</runCoverage>
            <formats>
                <format>html</format>
            </formats>
            <failBuild>false</failBuild>
        </coverage>
    </configuration>
</plugin>"""


def get_full_version_map() -> Dict:
    """Return the full map — used by the API endpoint."""
    return {
        k: {
            "series": v["series"],
            "versions": v["versions"],
            "recommended": v["recommended"],
            "plugin": v["plugin"],
        }
        for k, v in _RUNTIME_MUNIT_MAP.items()
    }
