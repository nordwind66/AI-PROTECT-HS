"""A small JSON Schema (draft 2020-12 subset) validator -- standard library only.

The build machine has no `jsonschema` package and installing one was out of scope, but the documents of this
project (rule snapshot, manifest, request / response, configuration, rule specifications) have schemas in
schemas/*.json that must be CHECKED, not just written.  This validator implements exactly the keywords those
schemas use:

    $ref (local, "#" and "#/$defs/..."), type, enum, const, required, properties, additionalProperties,
    propertyNames (pattern), minProperties, maxProperties, items, prefixItems, minItems, maxItems, uniqueItems,
    minimum, maximum, exclusiveMinimum, exclusiveMaximum, minLength, maxLength, pattern, oneOf, anyOf, allOf,
    not, if / then / else.

Annotation keywords (title, description, default, examples, $schema, $id, $defs) are ignored.  An unknown
validation keyword raises SchemaError instead of being silently skipped.

    errors = validate(instance, schema)     # list of "path: message" strings, empty = valid
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

ANNOTATIONS = {"$schema", "$id", "$defs", "title", "description", "default", "examples", "$comment", "deprecated"}
KNOWN = {"$ref", "type", "enum", "const", "required", "properties", "additionalProperties", "propertyNames",
         "minProperties", "maxProperties", "items", "prefixItems", "minItems", "maxItems", "uniqueItems", "minimum",
         "maximum", "exclusiveMinimum", "exclusiveMaximum", "minLength", "maxLength", "pattern", "oneOf", "anyOf",
         "allOf", "not", "if", "then", "else"}


class SchemaError(ValueError):
    pass


def load_schema(path: Path) -> Dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _is_type(value: Any, name: str) -> bool:
    if name == "null":
        return value is None
    if name == "boolean":
        return isinstance(value, bool)
    if name == "integer":
        return (isinstance(value, int) and not isinstance(value, bool)) or (isinstance(value, float) and value.is_integer())
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if name == "string":
        return isinstance(value, str)
    if name == "array":
        return isinstance(value, list)
    if name == "object":
        return isinstance(value, dict)
    raise SchemaError(f"unknown type {name!r}")


def _resolve(ref: str, root: Dict[str, Any]) -> Any:
    if ref == "#":
        return root
    if not ref.startswith("#/"):
        raise SchemaError(f"only local references are supported: {ref}")
    node: Any = root
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or part not in node:
            raise SchemaError(f"unresolvable reference {ref}")
        node = node[part]
    return node


def _same(a: Any, b: Any) -> bool:
    if isinstance(a, bool) != isinstance(b, bool):
        return False
    return a == b


def _check(value: Any, schema: Any, root: Dict[str, Any], path: str, errors: List[str]) -> None:
    if schema is True:
        return
    if schema is False:
        errors.append(f"{path}: not allowed here")
        return
    if not isinstance(schema, dict):
        raise SchemaError(f"schema at {path} is not an object")
    for key in schema:
        if key not in KNOWN and key not in ANNOTATIONS:
            raise SchemaError(f"unsupported schema keyword {key!r}")
    if "$ref" in schema:
        _check(value, _resolve(schema["$ref"], root), root, path, errors)
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_is_type(value, t) for t in types):
            errors.append(f"{path}: expected {' or '.join(types)}, got {type(value).__name__}")
            return
    if "enum" in schema and not any(_same(value, e) for e in schema["enum"]):
        errors.append(f"{path}: {value!r} is not one of {schema['enum']}")
    if "const" in schema and not _same(value, schema["const"]):
        errors.append(f"{path}: must be {schema['const']!r}")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: {value} < minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: {value} > maximum {schema['maximum']}")
        if "exclusiveMinimum" in schema and value <= schema["exclusiveMinimum"]:
            errors.append(f"{path}: {value} <= exclusiveMinimum {schema['exclusiveMinimum']}")
        if "exclusiveMaximum" in schema and value >= schema["exclusiveMaximum"]:
            errors.append(f"{path}: {value} >= exclusiveMaximum {schema['exclusiveMaximum']}")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path}: shorter than {schema['minLength']}")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{path}: longer than {schema['maxLength']}")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            errors.append(f"{path}: {value[:60]!r} does not match {schema['pattern']}")
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path}: fewer than {schema['minItems']} items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: more than {schema['maxItems']} items")
        if schema.get("uniqueItems"):
            seen: List[Any] = []
            for item in value:
                if any(_same(item, s) for s in seen):
                    errors.append(f"{path}: items are not unique")
                    break
                seen.append(item)
        prefix = schema.get("prefixItems", [])
        for i, sub in enumerate(prefix):
            if i < len(value):
                _check(value[i], sub, root, f"{path}[{i}]", errors)
        if "items" in schema:
            for i in range(len(prefix), len(value)):
                _check(value[i], schema["items"], root, f"{path}[{i}]", errors)
    if isinstance(value, dict):
        if "minProperties" in schema and len(value) < schema["minProperties"]:
            errors.append(f"{path}: fewer than {schema['minProperties']} properties")
        if "maxProperties" in schema and len(value) > schema["maxProperties"]:
            errors.append(f"{path}: more than {schema['maxProperties']} properties")
        for req in schema.get("required", []):
            if req not in value:
                errors.append(f"{path}: missing required property {req!r}")
        props = schema.get("properties", {})
        for k, v in value.items():
            if "propertyNames" in schema:
                pn = schema["propertyNames"]
                if "pattern" in pn and re.search(pn["pattern"], k) is None:
                    errors.append(f"{path}: property name {k!r} does not match {pn['pattern']}")
            if k in props:
                _check(v, props[k], root, f"{path}.{k}" if path else k, errors)
            elif "additionalProperties" in schema:
                ap = schema["additionalProperties"]
                if ap is False:
                    errors.append(f"{path}: unexpected property {k!r}")
                elif ap is not True:
                    _check(v, ap, root, f"{path}.{k}" if path else k, errors)

    if "allOf" in schema:
        for sub in schema["allOf"]:
            _check(value, sub, root, path, errors)
    if "anyOf" in schema:
        if not any(_valid(value, sub, root) for sub in schema["anyOf"]):
            errors.append(f"{path}: matches none of the anyOf alternatives")
    if "oneOf" in schema:
        n = sum(1 for sub in schema["oneOf"] if _valid(value, sub, root))
        if n != 1:
            errors.append(f"{path}: matches {n} of the oneOf alternatives (exactly 1 required)"
                          + ("" if n else "; " + "; ".join(_first_errors(value, sub, root, path) for sub in schema["oneOf"])[:300]))
    if "not" in schema and _valid(value, schema["not"], root):
        errors.append(f"{path}: must not match the 'not' schema")
    if "if" in schema:
        branch = schema.get("then") if _valid(value, schema["if"], root) else schema.get("else")
        if branch is not None:
            _check(value, branch, root, path, errors)


def _valid(value: Any, schema: Any, root: Dict[str, Any]) -> bool:
    errs: List[str] = []
    _check(value, schema, root, "", errs)
    return not errs


def _first_errors(value: Any, schema: Any, root: Dict[str, Any], path: str) -> str:
    errs: List[str] = []
    _check(value, schema, root, path, errs)
    return errs[0] if errs else "ok"


def validate(instance: Any, schema: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    _check(instance, schema, schema, "$", errors)
    return errors


def assert_valid(instance: Any, schema: Dict[str, Any], what: str = "document") -> None:
    errors = validate(instance, schema)
    if errors:
        raise AssertionError(f"{what} violates its schema:\n  " + "\n  ".join(errors[:20]))
