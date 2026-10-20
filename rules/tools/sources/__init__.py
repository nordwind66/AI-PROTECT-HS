"""Source importer plugins (discovered by name from third_party/sources.def.json "importer")."""
from __future__ import annotations

import importlib
from typing import Dict

from .base import SourceImporter

_REGISTRY: Dict[str, str] = {
    # importer id -> "module:ClassName"   (add a line here for a fourth rule source)
    "atr": "sources.atr:AtrImporter",
    "trans_pid": "sources.trans_pid:TransImporter",
    "fevzi_pidr": "sources.fevzi_pidr:FevziImporter",
}


def get_importer(importer_id: str) -> SourceImporter:
    try:
        target = _REGISTRY[importer_id]
    except KeyError:
        raise KeyError(f"no importer plugin named {importer_id!r}; known: {', '.join(sorted(_REGISTRY))}") from None
    mod_name, cls_name = target.split(":")
    return getattr(importlib.import_module(mod_name), cls_name)()


def importer_ids():
    return sorted(_REGISTRY)
