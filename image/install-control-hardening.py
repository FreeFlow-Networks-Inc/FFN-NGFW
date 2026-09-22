#!/usr/bin/env python3
"""Merge shared authorization and durable edit locks without replacing live handlers."""
import ast
from pathlib import Path


def merge_manager(source, wanted):
    def functions(text):
        tree = ast.parse(text)
        result = {}
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                result[node.name] = node
            elif isinstance(node, ast.ClassDef) and node.name == 'ConfigManager':
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        result['ConfigManager.'+child.name] = child
        return result
    old, new = functions(source), functions(wanted)
    lines, desired = source.splitlines(keepends=True), wanted.splitlines(keepends=True)
    edits = []
    for name in ('get_current_user','ConfigManager.lock_status','ConfigManager.acquire_lock',
                 'ConfigManager.release_lock','config_lock_override'):
        before, after = old[name], new[name]
        edits.append((before.lineno-1,before.end_lineno,desired[after.lineno-1:after.end_lineno]))
    for start,end,replacement in sorted(edits,reverse=True):lines[start:end]=replacement
    source = ''.join(lines)
    before = '        self._lock_holder: Optional[str] = None\n        self._lock_acquired_at: float = 0\n        self._lock_reason: str = ""\n'
    after = "        from ffn_config_lock import ConfigLock\n        self._config_lock = ConfigLock(CONFIG_DIR / 'config-lock.sqlite3', COMMIT_LOCK_TIMEOUT)\n"
    if after not in source:
        if source.count(before) != 1:raise ValueError('Unknown configuration lock initialization')
        source = source.replace(before,after)
    compile(source,'ffn_manager.py','exec')
    return source
