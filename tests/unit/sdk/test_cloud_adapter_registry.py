"""Wiring smoke test for the cloud-native adapters (ADR-0012).

Confirms the new registry keys resolve to importable adapter classes WITHOUT instantiating them (the
google-cloud SDKs are an optional ``[gcp]`` extra, imported lazily inside the adapter constructors —
so module import + class lookup must work even when the SDKs are absent).
"""

from __future__ import annotations

import importlib

import pytest

from quaicu.delivery.sdk.kernel import _ADAPTER_REGISTRY


@pytest.mark.parametrize(
    "key, expected_class",
    [
        ("vertex_inference", "VertexInferenceAdapter"),
        ("gcp_kms_ledger", "GcpKmsLedgerAdapter"),
    ],
)
def test_cloud_adapter_key_resolves_to_importable_class(key: str, expected_class: str):
    assert key in _ADAPTER_REGISTRY, f"{key!r} missing from the adapter registry"
    module_path, class_name = _ADAPTER_REGISTRY[key]
    assert class_name == expected_class
    module = importlib.import_module(module_path)  # lazy SDK import is inside __init__, not here
    assert hasattr(module, class_name), f"{module_path}.{class_name} not found"
