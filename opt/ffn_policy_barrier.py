"""Core optional policy boundary. Generic platforms never load hardware code."""
import asyncio
from pathlib import Path


async def before_commit(app,candidate):
    guard=getattr(app.state,'platform_policy_guard',None)
    if guard is None:return None
    # A configured but failed selected extension must not silently bypass its
    # policy barrier. Exceptions propagate and prevent the running commit.
    return await asyncio.to_thread(guard,Path(candidate).read_bytes())
