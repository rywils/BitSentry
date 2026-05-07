from typing import List
from plugins.base_plugin import BasePlugin

def resolve_plugins(
    plugins: List[BasePlugin],
    include: str | None = None,
    exclude: str | None = None,
) -> List[BasePlugin]:

    plugin_map = {p.name: p for p in plugins}

    # Default = all
    enabled = set(plugin_map.keys())

    if include:
        enabled = set(name.strip() for name in include.split(','))

    if exclude:
        for name in exclude.split(','):
            enabled.discard(name.strip())

    selected = [plugin_map[name] for name in enabled if name in plugin_map]

    if not selected:
        raise RuntimeError("No plugins selected after include/exclude resolution")

    return selected
