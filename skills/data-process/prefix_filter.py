"""BGPStream prefix filters for event data collection."""


def bgpstream_prefix_filters(prefix: str) -> list[str]:
    """Return filters for the event prefix, more-specifics, and covering prefixes.

    BGPStream does not implement ``or`` in filter strings, so more-specifics
    and less-specifics must be collected in separate passes. Both ``prefix more
    P`` and ``prefix less P`` include P itself.
    """
    prefix = str(prefix or "").strip()
    if not prefix:
        raise ValueError("prefix is required")
    return [
        f"prefix more {prefix}",
        f"prefix less {prefix}",
    ]


def bgpstream_prefix_filter(prefix: str) -> str:
    """Deprecated single-string form; BGPStream cannot parse the embedded or."""
    return " or ".join(bgpstream_prefix_filters(prefix))
