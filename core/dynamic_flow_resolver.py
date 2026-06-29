"""
core/dynamic_flow_resolver.py
─────────────────────────────
Statically resolves dynamic flow references in Mule 4 XML.

Problem statement
─────────────────
A Mule flow can call another flow in several non-obvious ways:

  1. Literal flow-ref          <flow-ref name="OrderFlow"/>
  2. Variable flow-ref         <flow-ref name="#[vars.targetFlow]"/>
  3. Conditional assignment    choice → set-variable → flow-ref
  4. DW inline conditional     <flow-ref name="#[if (vars.type=='A') 'FlowA' else 'FlowB']"/>
  5. String concatenation      <flow-ref name="#['process-' ++ vars.type ++ '-flow']"/>
  6. Map / dict dispatch       <flow-ref name="#[{order:'OrderFlow',invoice:'InvoiceFlow'}[vars.type]]"/>
  7. DataWeave lookup()        lookup("ProcessFlow", payload)  inside <ee:transform>
  8. DW lookup with variable   lookup(vars.targetFlow, payload)
  9. DW lookup with concat     lookup("process-" ++ vars.type ++ "-flow", payload)

Cases 1 and 7 (literal string) are already handled.
Cases 2–9 require the static analysis this module provides.

How it works
────────────
Phase A — VariableValueMap
  Walk the *entire* flow XML tree (including nested choice branches, error
  handlers, async blocks, until-successful) and collect every string literal
  ever assigned to every variable, regardless of whether that branch is
  actually executed. This gives the over-approximation we need for safe
  static analysis: "these are ALL flows this flow COULD call."

Phase B — Expression Resolver
  Given an expression like #[vars.targetFlow] or
  #['process-' ++ vars.type ++ '-flow'], apply a cascade of strategies:
    S1. Direct string literal              #['OrderFlow']
    S2. Variable lookup in VariableValueMap vars.targetFlow
    S3. DW if/else extraction             if (x) 'FlowA' else 'FlowB'
    S4. String concat + known-name match  'prefix-' ++ vars.x ++ '-suffix'
    S5. Map value extraction              {a: 'FlowA', b: 'FlowB'}[vars.key]
    S6. Last-resort literal scan          any quoted string that is a known flow name

Phase C — DW lookup() extraction
  Scan all text content and attribute values for lookup(expr, ...) calls.
  Resolve `expr` with the same Phase-B cascade.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Set


# ─── Regex constants ──────────────────────────────────────────────────────────

# Match any quoted string inside a DW expression
_QUOTED_RE = re.compile(r"""['"]([^'"]{1,200})['"]""")

# Variable name from vars.x or variables.x
_VAR_REF_RE = re.compile(r"""\b(?:vars|variables)\.([A-Za-z_][A-Za-z0-9_\-]*)""")

# References to object fields: vars.route.flowName, payload.flowName, payload['flowName']
_REF_DOT_RE = re.compile(
    r"""\b(vars|variables|payload|attributes)\.([A-Za-z_][A-Za-z0-9_\-]*(?:\.[A-Za-z_][A-Za-z0-9_\-]*)*)"""
)
_REF_BRACKET_RE = re.compile(
    r"""\b(vars|variables|payload|attributes)(?:\.([A-Za-z_][A-Za-z0-9_\-]*))?\s*\[\s*['"]([^'"]+)['"]\s*\]"""
)

# DW if/else:  if (cond) 'X' else 'Y'
_DW_IF_ELSE_RE = re.compile(
    r"""if\s*\([^)]{0,200}\)\s*['"]([^'"]+)['"]\s*else\s*['"]([^'"]+)['"]"""
)

# String concatenation prefix: 'prefix-' ++ ...
_CONCAT_PREFIX_RE = re.compile(r"""['"]([A-Za-z0-9][\w\-]*)['"]\s*\+\+""")

# String concatenation suffix: ... ++ 'suffix'
_CONCAT_SUFFIX_RE = re.compile(r"""\+\+\s*['"]([A-Za-z0-9][\w\-]*['"]?)""")

# Map literal: {key: 'FlowName', ...}
_MAP_VALUE_RE = re.compile(r"""[\w\d]+\s*:\s*['"]([^'"]{2,100})['"]""")

# DataWeave / JSON-style object fields: {"flowName": "FlowA"} or {flowName: 'FlowA'}
_OBJECT_FIELD_RE = re.compile(
    r"""['"]?([A-Za-z_][A-Za-z0-9_\-]*)['"]?\s*:\s*['"]([^'"]{1,200})['"]"""
)

# DataWeave lookup() call  — captures the first argument expression
_DW_LOOKUP_RE = re.compile(
    r"""lookup\s*\(\s*(['"][^'"]+['"]|[^\s,)]{1,200})\s*,""",
    re.DOTALL,
)

# Elements whose text/attributes we need to scan for DWL content
_DWL_BEARING_TAGS = {
    "set-payload", "set-variable", "transform", "message", "variables",
    "set-event", "expression", "when", "criteria",
}


# ─── Public API ───────────────────────────────────────────────────────────────

class DynamicFlowResolver:
    """
    Resolve dynamic flow references statically by analysing the whole flow XML.

    Usage (from XMLAnalyzer._extract_flow_details):
        resolver = DynamicFlowResolver(all_flow_names)
        resolver.scan_element(flow_xml_element)
        resolved = resolver.resolve_all()
        # resolved.static_refs     — literal flow-ref names
        # resolved.dynamic_refs    — resolved dynamic flow-ref names
        # resolved.dw_lookup_refs  — resolved lookup() targets
        # resolved.unresolved      — expressions that couldn't be resolved
    """

    def __init__(self, all_flow_names: Set[str]):
        """
        Parameters
        ----------
        all_flow_names : set of every flow / sub-flow name in the entire project.
            Used by strategies S4 and S5 for prefix/suffix matching.
        """
        self._all_names: Set[str] = all_flow_names or set()

        # VariableValueMap: var_name → set of possible string values
        self._var_values: Dict[str, Set[str]] = {}

        # Raw dynamic expressions collected during scan
        self._dynamic_flow_ref_exprs: List[str] = []  # from <flow-ref name="#[...]">
        self._dw_lookup_exprs: List[str] = []          # first arg of lookup()

    # ── Phase A: scan ────────────────────────────────────────────────────────

    def scan_element(self, root: ET.Element) -> "DynamicFlowResolver":
        """Walk the entire flow element tree and collect all relevant data."""
        self._walk(root)
        return self

    def _walk(self, element: ET.Element) -> None:
        local = _local(element.tag)

        # ── Collect variable assignments ──────────────────────────────────
        if local == "set-variable":
            vname = (
                element.attrib.get("variableName")
                or element.attrib.get("variable_name")
                or element.attrib.get("target")
                or ""
            )
            value = element.attrib.get("value", "")
            if vname:
                for field, lit in self._extract_object_string_fields(value).items():
                    self._record_var(f"{vname}.{field}", lit)
                    if field.lower() in {"flowname", "flow_name", "targetflow", "target_flow"}:
                        self._record_var(vname, lit)
                for lit in self._extract_string_literals(value):
                    self._record_var(vname, lit)
                if _is_dynamic(value):
                    # DW expression — extract quoted string literals inside it
                    for lit in self._extract_string_literals(value):
                        self._record_var(vname, lit)
                    # Also check for inline conditional: #[if (x) 'A' else 'B']
                    inner = value[2:-1].strip() if value.startswith("#[") else value
                    for m in _DW_IF_ELSE_RE.finditer(inner):
                        self._record_var(vname, m.group(1))
                        self._record_var(vname, m.group(2))
                elif value and not value.startswith("{") and len(value) < 200:
                    # Plain string value (most common case): value="MyFlow"
                    self._record_var(vname, value.strip())
                element_text = element.text or ""
                if element_text.strip():
                    for field, lit in self._extract_object_string_fields(element_text).items():
                        self._record_var(f"{vname}.{field}", lit)
                        if field.lower() in {"flowname", "flow_name", "targetflow", "target_flow"}:
                            self._record_var(vname, lit)
                    for lit in self._extract_string_literals(element_text):
                        self._record_var(vname, lit)
                    if len(element_text.strip()) < 200:
                        self._record_var(vname, element_text.strip())
                # Also scan inline DWL content in child elements (rare)
                for child in element:
                    child_text = child.text or ""
                    for field, lit in self._extract_object_string_fields(child_text).items():
                        self._record_var(f"{vname}.{field}", lit)
                        if field.lower() in {"flowname", "flow_name", "targetflow", "target_flow"}:
                            self._record_var(vname, lit)
                    for lit in self._extract_string_literals(child_text):
                        self._record_var(vname, lit)
                    if _is_dynamic(child_text):
                        for lit in self._extract_string_literals(child_text):
                            self._record_var(vname, lit)
                    elif child_text.strip():
                        self._record_var(vname, child_text.strip())

        if local in {"set-payload", "set-attributes"}:
            scope = "attributes" if local == "set-attributes" else "payload"
            texts = [element.text or "", element.attrib.get("value", "")]
            texts.extend(child.text or "" for child in element)
            for text in texts:
                for field, lit in self._extract_object_string_fields(text).items():
                    self._record_var(f"{scope}.{field}", lit)

        # ── Collect flow-ref name expressions ────────────────────────────
        if local == "flow-ref":
            name_expr = element.attrib.get("name", "")
            if _is_dynamic(name_expr):
                self._dynamic_flow_ref_exprs.append(name_expr)
            # (static ones are handled by the caller)

        # ── Scan for DataWeave lookup() calls ────────────────────────────
        self._scan_text_for_lookups(element.text or "")
        for attr_val in element.attrib.values():
            self._scan_text_for_lookups(attr_val)

        # Recurse into children
        for child in element:
            self._walk(child)

    def _scan_text_for_lookups(self, text: str) -> None:
        """Extract all lookup() first-argument expressions from text."""
        if "lookup" not in text:
            return
        # Find each lookup( occurrence and manually extract the first argument
        # (up to the first top-level comma) so we handle embedded quotes in
        # concat expressions like lookup("prefix-" ++ vars.x ++ "-suffix", payload)
        search_from = 0
        while True:
            idx = text.find("lookup(", search_from)
            if idx == -1:
                break
            # Move past "lookup("
            start = idx + len("lookup(")
            # Find the first comma at depth 0 (not inside nested parens)
            depth = 0
            end = start
            while end < len(text):
                ch = text[end]
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    if depth == 0:
                        break  # end of lookup call with no comma — edge case
                    depth -= 1
                elif ch == "," and depth == 0:
                    break
                end += 1
            arg = text[start:end].strip()
            if arg:
                self._dw_lookup_exprs.append(arg)
            search_from = end + 1

    def _record_var(self, name: str, value: str) -> None:
        if not name or not value:
            return
        if name not in self._var_values:
            self._var_values[name] = set()
        self._var_values[name].add(value.strip())

    # ── Phase B: resolve ─────────────────────────────────────────────────────

    def resolve_all(self) -> "ResolvedRefs":
        dynamic_refs: List[str] = []
        dw_lookup_refs: List[str] = []
        unresolved: List[str] = []

        for expr in self._dynamic_flow_ref_exprs:
            resolved = self._resolve_expression(expr)
            if resolved:
                dynamic_refs.extend(r for r in resolved if r not in dynamic_refs)
            else:
                unresolved.append(expr)

        for expr in self._dw_lookup_exprs:
            resolved = self._resolve_expression(expr)
            if resolved:
                dw_lookup_refs.extend(r for r in resolved if r not in dw_lookup_refs)
            else:
                # Could be a literal wrapped in quotes
                inner = expr.strip("'\"")
                if inner and inner in self._all_names:
                    dw_lookup_refs.append(inner)
                else:
                    unresolved.append(f"lookup({expr})")

        return ResolvedRefs(
            dynamic_refs=dynamic_refs,
            dw_lookup_refs=dw_lookup_refs,
            unresolved=unresolved,
            var_value_map={k: sorted(v) for k, v in self._var_values.items()},
        )

    def _resolve_expression(self, expr: str) -> List[str]:
        """Apply strategy cascade and return all candidate flow names."""
        # Unwrap #[...] wrapper
        inner = expr.strip()
        if inner.startswith("#[") and inner.endswith("]"):
            inner = inner[2:-1].strip()

        found: List[str] = []

        # S1 — Direct literal
        self._s1_literal(inner, found)
        if found:
            return found

        # S3 — DW if/else (before var lookup so we catch inline conditions)
        self._s3_dw_if_else(inner, found)

        # S5 — Map value extraction
        self._s5_map_values(inner, found)

        # S2 — Variable reference → look up collected values
        self._s2_variable_lookup(inner, found)

        # S4 — String concatenation prefix/suffix match
        self._s4_concat_pattern(inner, found)

        # S6 — Last resort: any quoted string that is a known flow name
        if not found:
            self._s6_literal_scan(inner, found)

        return found

    # ── Strategies ────────────────────────────────────────────────────────────

    def _s1_literal(self, inner: str, out: List[str]) -> None:
        """Single quoted/double-quoted string that is a known flow name."""
        m = re.match(r"""^['"]([^'"]+)['"]$""", inner.strip())
        if m:
            name = m.group(1)
            if name in self._all_names:
                _add(out, name)

    def _s2_variable_lookup(self, inner: str, out: List[str]) -> None:
        """Resolve vars.x / variables.x / payload.x from the collected value map."""
        for var_name in self._reference_keys(inner):
            for value in self._var_values.get(var_name, set()):
                # The value itself might be an expression — recursively resolve
                sub = self._resolve_expression(value) if _is_dynamic(value) else []
                if sub:
                    for s in sub:
                        _add(out, s)
                elif value in self._all_names:
                    _add(out, value)
                # Also try direct match of the value after stripping quotes
                stripped = value.strip("'\"")
                if stripped in self._all_names:
                    _add(out, stripped)

    def _s3_dw_if_else(self, inner: str, out: List[str]) -> None:
        """
        Handle: if (condition) 'FlowA' else 'FlowB'
        Also handles nested: if (a) 'X' else if (b) 'Y' else 'Z'
        """
        # Multi-branch: collect all quoted strings that appear after 'if' / 'else'
        branch_re = re.compile(
            r"""(?:if\s*\([^)]{0,200}\)|else\s+if\s*\([^)]{0,200}\)|else)\s*['"]([^'"]+)['"]""",
            re.DOTALL,
        )
        for m in branch_re.finditer(inner):
            name = m.group(1)
            if name in self._all_names:
                _add(out, name)

        # Fallback: standard if/else pattern
        for m in _DW_IF_ELSE_RE.finditer(inner):
            for name in (m.group(1), m.group(2)):
                if name in self._all_names:
                    _add(out, name)

    def _s4_concat_pattern(self, inner: str, out: List[str]) -> None:
        """
        Handle string concatenation: 'prefix-' ++ vars.x ++ '-suffix'
        Match against known flow names using the extracted prefix/suffix.
        """
        prefixes = [m.group(1) for m in _CONCAT_PREFIX_RE.finditer(inner)]
        # suffix regex already strips trailing quote — clean up
        suffixes = []
        for m in _CONCAT_SUFFIX_RE.finditer(inner):
            s = m.group(1).rstrip("'\"")
            if s:
                suffixes.append(s)

        if not prefixes and not suffixes:
            return

        for name in self._all_names:
            prefix_ok = not prefixes or any(name.startswith(p) for p in prefixes)
            suffix_ok = not suffixes or any(name.endswith(s) for s in suffixes)
            if prefix_ok and suffix_ok:
                _add(out, name)

        # Also try substituting known variable values into the concat expression
        for var_name in self._reference_keys(inner):
            for val in self._var_values.get(var_name, set()):
                # Replace vars.x with the known value and build candidate
                candidate = inner
                for vr in [f"vars.{var_name}", f"variables.{var_name}", var_name]:
                    candidate = candidate.replace(vr, val.strip("'\""))
                # Remove ++ and quotes, concatenate
                parts = re.split(r'\+\+', candidate)
                joined = "".join(p.strip().strip("'\"") for p in parts)
                if joined in self._all_names:
                    _add(out, joined)

    def _s5_map_values(self, inner: str, out: List[str]) -> None:
        """
        Handle map/dict dispatch:
          {order: 'OrderFlow', invoice: 'InvoiceFlow'}[vars.type]
        Extract all values from the map literal.
        """
        for m in _MAP_VALUE_RE.finditer(inner):
            name = m.group(1)
            if name in self._all_names:
                _add(out, name)

    def _s6_literal_scan(self, inner: str, out: List[str]) -> None:
        """Last resort: scan for any quoted string that is a known flow name."""
        for m in _QUOTED_RE.finditer(inner):
            name = m.group(1)
            if name in self._all_names:
                _add(out, name)

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_string_literals(text: str) -> List[str]:
        """Return all single/double quoted string literals from a DW expression."""
        return [m.group(1) for m in _QUOTED_RE.finditer(text or "")]

    @staticmethod
    def _extract_object_string_fields(text: str) -> Dict[str, str]:
        """Return object field string values from DW/JSON-like object literals."""
        fields: Dict[str, str] = {}
        for m in _OBJECT_FIELD_RE.finditer(text or ""):
            fields[m.group(1)] = m.group(2)
        return fields

    @staticmethod
    def _reference_keys(text: str) -> List[str]:
        """Return value-map keys referenced by a DW expression."""
        keys: List[str] = []

        def add(key: str) -> None:
            if key and key not in keys:
                keys.append(key)

        for scope, path in _REF_DOT_RE.findall(text or ""):
            if scope in {"payload", "attributes"}:
                add(f"{scope}.{path}")
                if "." in path:
                    add(f"{scope}.{path.split('.')[-1]}")
            else:
                add(path)
                add(path.split(".", 1)[0])

        for scope, base, field in _REF_BRACKET_RE.findall(text or ""):
            if scope in {"payload", "attributes"}:
                add(f"{scope}.{field}" if not base else f"{scope}.{base}.{field}")
            elif base:
                add(f"{base}.{field}")
                add(base)
            else:
                add(field)

        for var_name in _VAR_REF_RE.findall(text or ""):
            add(var_name)
        return keys


# ─── Result dataclass ─────────────────────────────────────────────────────────

class ResolvedRefs:
    """Outcome of a DynamicFlowResolver.resolve_all() call."""

    __slots__ = ("dynamic_refs", "dw_lookup_refs", "unresolved", "var_value_map")

    def __init__(
        self,
        dynamic_refs: List[str],
        dw_lookup_refs: List[str],
        unresolved: List[str],
        var_value_map: Dict[str, List[str]],
    ):
        self.dynamic_refs = dynamic_refs
        self.dw_lookup_refs = dw_lookup_refs
        self.unresolved = unresolved
        self.var_value_map = var_value_map

    @property
    def all_refs(self) -> List[str]:
        seen: Set[str] = set()
        result = []
        for r in self.dynamic_refs + self.dw_lookup_refs:
            if r not in seen:
                seen.add(r)
                result.append(r)
        return result

    def to_dict(self) -> dict:
        return {
            "dynamic_refs": self.dynamic_refs,
            "dw_lookup_refs": self.dw_lookup_refs,
            "unresolved": self.unresolved,
            "var_value_map": self.var_value_map,
        }


# ─── Module-level convenience function ───────────────────────────────────────

def resolve_dynamic_refs(
    flow_element: ET.Element,
    all_flow_names: Set[str],
) -> ResolvedRefs:
    """
    One-shot: scan a flow XML element and return all resolved dynamic refs.

    Parameters
    ----------
    flow_element  : the <flow> or <sub-flow> ET.Element
    all_flow_names: set of every flow name in the project (for matching)

    Returns
    -------
    ResolvedRefs with .dynamic_refs, .dw_lookup_refs, .unresolved
    """
    resolver = DynamicFlowResolver(all_flow_names)
    resolver.scan_element(flow_element)
    return resolver.resolve_all()


# ─── Private helpers ──────────────────────────────────────────────────────────

def _local(tag: str) -> str:
    """Strip XML namespace from a tag."""
    return re.sub(r"\{[^}]+\}", "", tag)


def _is_dynamic(expr: str) -> bool:
    """Return True if the expression contains a DW expression or variable."""
    return "#[" in expr or "vars." in expr or "++" in expr


def _add(lst: List[str], value: str) -> None:
    """Append value to list if not already present."""
    if value and value not in lst:
        lst.append(value)
