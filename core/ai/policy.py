"""Tool and external-data policy enforcement for the WatchTower analyst."""

from __future__ import annotations

from ipaddress import ip_address
from uuid import UUID
from typing import Any

from core.ai.contracts import RunPolicy, ScopedContext, ToolManifest
from core.ai.redaction import contains_sensitive_external_data


class PolicyError(PermissionError):
    pass


class ApprovalRequired(PolicyError):
    pass


def validate_input_schema(schema: dict, arguments: Any) -> None:
    """Validate the bounded JSON-Schema subset used by local tool manifests.

    Keeping this small makes tool contracts deterministic without granting
    model output any executable interpretation. Unknown fields are rejected
    unless a manifest deliberately opts into them.
    """
    schema = schema or {}
    if not schema:
        if arguments:
            raise PolicyError("This AI tool does not accept arguments")
        return
    _validate(schema, arguments, "arguments")


def _validate(schema: dict, value: Any, path: str) -> None:
    alternatives = schema.get("anyOf") or ()
    if alternatives:
        errors = []
        for alternative in alternatives:
            try:
                _validate(alternative, value, path)
                return
            except PolicyError as exc:
                errors.append(str(exc))
        raise PolicyError(errors[0] if errors else f"{path} does not match the input contract")
    expected = schema.get("type")
    if expected == "object":
        if not isinstance(value, dict):
            raise PolicyError(f"{path} must be an object")
        properties = schema.get("properties") or {}
        for name in schema.get("required") or ():
            if name not in value:
                raise PolicyError(f"{path}.{name} is required")
        if schema.get("additionalProperties") is not True:
            unknown = set(value) - set(properties)
            if unknown:
                raise PolicyError(f"{path} contains unsupported field(s): {', '.join(sorted(unknown))}")
        for name, child in properties.items():
            if name in value:
                _validate(child, value[name], f"{path}.{name}")
        return
    if expected == "array":
        if not isinstance(value, list):
            raise PolicyError(f"{path} must be an array")
        if "minItems" in schema and len(value) < int(schema["minItems"]):
            raise PolicyError(f"{path} has too few values")
        if "maxItems" in schema and len(value) > int(schema["maxItems"]):
            raise PolicyError(f"{path} has too many values")
        for index, item in enumerate(value):
            _validate(schema.get("items") or {}, item, f"{path}[{index}]")
        return
    if expected == "string" and not isinstance(value, str):
        raise PolicyError(f"{path} must be a string")
    if expected == "integer" and (not isinstance(value, int) or isinstance(value, bool)):
        raise PolicyError(f"{path} must be an integer")
    if expected == "boolean" and not isinstance(value, bool):
        raise PolicyError(f"{path} must be a boolean")
    if "enum" in schema and value not in schema["enum"]:
        raise PolicyError(f"{path} must be one of: {', '.join(str(item) for item in schema['enum'])}")
    if "minimum" in schema and value < schema["minimum"]:
        raise PolicyError(f"{path} is below the minimum")
    if "maximum" in schema and value > schema["maximum"]:
        raise PolicyError(f"{path} is above the maximum")


def validate_tool_call(manifest: ToolManifest, arguments: Any, scope: ScopedContext, policy: RunPolicy) -> None:
    if policy.mode == "general":
        raise PolicyError("General chat has no WatchTower data or action tools")
    if manifest.name not in set(policy.allowed_tools):
        raise PolicyError(f"AI tool {manifest.name} is not enabled for this run")
    validate_input_schema(manifest.input_schema, arguments)
    if manifest.requires_scope and not scope.has_scope():
        raise PolicyError(f"AI tool {manifest.name} requires a capture scope")
    _validate_semantic_arguments(arguments)
    if manifest.active and not policy.allow_active_actions:
        raise PolicyError(f"AI tool {manifest.name} is not allowed by this run policy")
    if manifest.allows_external_network:
        if not policy.allow_external_network:
            raise PolicyError(f"AI tool {manifest.name} cannot use external research in this run")
        if contains_sensitive_external_data(arguments) and not policy.allow_sensitive_external:
            raise ApprovalRequired("External research would include sensitive local context")


def _validate_semantic_arguments(arguments: Any) -> None:
    """Reject identifiers that are syntactically valid JSON but semantically unsafe.

    This catches the observed UUID-as-IP failure before a lookup or investigation
    reaches the data layer. Tool schemas remain provider-neutral; semantic checks
    live at the policy boundary where every provider is subject to them.
    """
    if not isinstance(arguments, dict):
        return
    for key, value in arguments.items():
        if value is None:
            continue
        lowered = str(key).casefold()
        if lowered in {"ip", "source_ip", "target_ip", "address"}:
            if not isinstance(value, str):
                raise PolicyError(f"arguments.{key} must be an IP address")
            try:
                ip_address(value)
            except ValueError as exc:
                raise PolicyError(f"arguments.{key} must be an IP address, not a session or flow identifier") from exc
        if lowered.endswith("session_id") or lowered in {"case_id", "node_id"}:
            if lowered.endswith("session_id") and value:
                try:
                    UUID(str(value))
                except (ValueError, AttributeError) as exc:
                    raise PolicyError(f"arguments.{key} must be a UUID") from exc


def requires_confirmation(manifest: ToolManifest, arguments: Any, scope: ScopedContext) -> bool:
    if manifest.risk_tier in {"confirm", "typed"}:
        return True
    if manifest.name == "research" and isinstance(arguments, dict) and arguments.get("web_provider") == "openai":
        return True
    return bool(manifest.allows_external_network and contains_sensitive_external_data(arguments))
