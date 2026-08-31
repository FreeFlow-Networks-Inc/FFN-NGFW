#!/usr/bin/env python3
"""
db_api.py -- FastAPI router for database management endpoints.

Provides REST endpoints to list, upload, reload, and modify the 15
NGFW database types.  Import this router in ffn_manager.py:

    from db_api import db_router
    app.include_router(db_router)

Database metadata (loaded status, entry counts, timestamps) is kept in
a local SQLite table so the manager can report state across restarts.
"""

import asyncio
import json
import logging
import os
import shutil
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import aiosqlite
from fastapi import APIRouter, HTTPException, UploadFile, File, Query
from pydantic import BaseModel

from db_compiler import (
    COMPILERS,
    BRAM_TYPES,
    DDR4_TYPES,
    BLOOM_TYPES,
    DB_TYPE_IDS,
    do_compile,
    do_load,
    do_update,
    _load_meta,
)

logger = logging.getLogger("ffn-db-api")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DB_PATH = os.getenv("FFN_DB_PATH", "/var/lib/ffn-ngfw/config.db")
DB_DIR = os.getenv("FFN_DB_DIR", "/etc/ffn-ngfw/databases")
FEED_URLS = {
    "threats":       "https://feeds.ffn-ngfw.example/threats.txt",
    "url":           "https://feeds.ffn-ngfw.example/url_categories.txt",
    "blocklist":     "https://feeds.ffn-ngfw.example/blocklist.txt",
    "dns_blocklist": "https://feeds.ffn-ngfw.example/dns_blocklist.txt",
    "malware_hashes":"https://feeds.ffn-ngfw.example/malware_hashes.txt",
    "geoip":         "https://feeds.ffn-ngfw.example/geoip.txt",
    "tls_fingerprints": "https://feeds.ffn-ngfw.example/tls_fingerprints.txt",
    "spyware_iocs":  "https://feeds.ffn-ngfw.example/spyware_iocs.txt",
}

db_router = APIRouter(prefix="/api/databases", tags=["databases"])

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class DatabaseEntry(BaseModel):
    """Generic key-value entry for adding a single row."""
    raw_line: str   # a single text line in the source-file format


class DatabaseStatus(BaseModel):
    db_type: str
    loaded: bool
    entry_count: int
    checksum: Optional[str] = None
    file_path: Optional[str] = None
    last_loaded: Optional[str] = None
    target: str  # "BRAM" or "DDR4" or "BRAM+DDR4"
    has_bloom: bool

# ---------------------------------------------------------------------------
# SQLite helpers
# ---------------------------------------------------------------------------

async def _ensure_db_tables():
    """Create the database_meta table if it does not exist."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS database_meta (
                db_type     TEXT NOT NULL,
                vsys        INTEGER NOT NULL DEFAULT 0,
                entry_count INTEGER NOT NULL DEFAULT 0,
                checksum    TEXT,
                file_path   TEXT,
                last_loaded TEXT,
                PRIMARY KEY (db_type, vsys)
            )
        """)
        await db.commit()


async def _get_db_meta(db_type: str, vsys: int = 0):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM database_meta WHERE db_type = ? AND vsys = ?",
            (db_type, vsys),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def _set_db_meta(db_type, vsys, entry_count, checksum, file_path):
    now = datetime.utcnow().isoformat() + "Z"
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO database_meta
                   (db_type, vsys, entry_count, checksum, file_path, last_loaded)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(db_type, vsys) DO UPDATE SET
                   entry_count = excluded.entry_count,
                   checksum    = excluded.checksum,
                   file_path   = excluded.file_path,
                   last_loaded = excluded.last_loaded
            """,
            (db_type, vsys, entry_count, checksum, file_path, now),
        )
        await db.commit()


async def _delete_db_meta(db_type, vsys=0):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "DELETE FROM database_meta WHERE db_type = ? AND vsys = ?",
            (db_type, vsys),
        )
        await db.commit()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _target_str(db_type: str) -> str:
    parts = []
    if db_type in BRAM_TYPES:
        parts.append("BRAM")
    if db_type in DDR4_TYPES:
        parts.append("DDR4")
    return "+".join(parts) if parts else "unknown"


def _source_path(db_type: str) -> Path:
    """Return the canonical on-disk path for a database file."""
    return Path(DB_DIR) / f"{db_type}.txt"


def _read_entries(file_path: str):
    """Read non-comment, non-empty lines from a database text file."""
    entries = []
    try:
        with open(file_path, "r") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if line and not line.startswith("#"):
                    entries.append({"id": i, "line": line})
    except FileNotFoundError:
        pass
    return entries

# ---------------------------------------------------------------------------
# Startup hook
# ---------------------------------------------------------------------------

@db_router.on_event("startup")
async def db_api_startup():
    await _ensure_db_tables()
    # Sync JSON metadata into SQLite (bridge from db_compiler CLI)
    meta = _load_meta()
    for key, info in meta.items():
        parts = key.split(":")
        db_type = parts[0]
        vsys = int(parts[1].replace("vsys", "")) if len(parts) > 1 else 0
        await _set_db_meta(
            db_type, vsys,
            info.get("entry_count", 0),
            info.get("checksum"),
            info.get("file_path"),
        )

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@db_router.get("")
async def list_databases():
    """List all 15 database types with loaded status and entry counts."""
    result = []
    for db_type in sorted(COMPILERS.keys()):
        meta = await _get_db_meta(db_type)
        result.append(DatabaseStatus(
            db_type=db_type,
            loaded=meta is not None and meta.get("entry_count", 0) > 0,
            entry_count=meta.get("entry_count", 0) if meta else 0,
            checksum=meta.get("checksum") if meta else None,
            file_path=meta.get("file_path") if meta else None,
            last_loaded=meta.get("last_loaded") if meta else None,
            target=_target_str(db_type),
            has_bloom=db_type in BLOOM_TYPES,
        ).dict())
    return {"databases": result, "count": len(result)}


@db_router.get("/{db_type}")
async def get_database(db_type: str, limit: int = Query(500, ge=1, le=10000),
                       offset: int = Query(0, ge=0)):
    """Show entries for a specific database type."""
    if db_type not in COMPILERS:
        raise HTTPException(status_code=404,
                            detail=f"Unknown database type: {db_type}")

    meta = await _get_db_meta(db_type)
    file_path = meta.get("file_path") if meta else str(_source_path(db_type))

    entries = _read_entries(file_path)
    total = len(entries)
    page = entries[offset : offset + limit]

    return {
        "db_type": db_type,
        "total": total,
        "offset": offset,
        "limit": limit,
        "entries": page,
        "meta": meta,
    }


@db_router.post("/{db_type}/upload")
async def upload_database(db_type: str, file: UploadFile = File(...),
                          vsys: int = Query(0, ge=0, le=255)):
    """Upload a new database file, compile it, and load into FPGA."""
    if db_type not in COMPILERS:
        raise HTTPException(status_code=404,
                            detail=f"Unknown database type: {db_type}")

    # Save uploaded file
    dest = _source_path(db_type)
    os.makedirs(dest.parent, exist_ok=True)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt",
                                     dir=str(dest.parent)) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        # Validate by compiling first
        result, payload, rc = do_compile(db_type, tmp_path)
        if rc != 0:
            raise HTTPException(status_code=400,
                                detail="Compilation failed -- check file format")

        # Move to canonical location
        shutil.move(tmp_path, str(dest))

        # Load into FPGA
        rc = do_load(db_type, str(dest), vsys=vsys)
        if rc != 0:
            raise HTTPException(status_code=500,
                                detail="FPGA load failed")

        entry_count = len(result[0]) if isinstance(result, tuple) else len(result)
        import zlib
        checksum = f"0x{zlib.crc32(payload) & 0xFFFFFFFF:08X}"
        await _set_db_meta(db_type, vsys, entry_count, checksum, str(dest))

        return {
            "status": "loaded",
            "db_type": db_type,
            "entry_count": entry_count,
            "checksum": checksum,
            "vsys": vsys,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


@db_router.post("/{db_type}/reload")
async def reload_database(db_type: str, vsys: int = Query(0, ge=0, le=255)):
    """Reload an existing database file from disk into the FPGA."""
    if db_type not in COMPILERS:
        raise HTTPException(status_code=404,
                            detail=f"Unknown database type: {db_type}")

    meta = await _get_db_meta(db_type, vsys)
    file_path = meta.get("file_path") if meta else str(_source_path(db_type))

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404,
                            detail=f"Source file not found: {file_path}")

    rc = do_load(db_type, file_path, vsys=vsys)
    if rc != 0:
        raise HTTPException(status_code=500, detail="FPGA load failed")

    # Re-read metadata from the JSON store
    from db_compiler import _load_meta as _lm
    fresh = _lm()
    key = f"{db_type}:vsys{vsys}"
    info = fresh.get(key, {})
    await _set_db_meta(
        db_type, vsys,
        info.get("entry_count", 0),
        info.get("checksum"),
        file_path,
    )

    return {"status": "reloaded", "db_type": db_type, "vsys": vsys}


@db_router.delete("/{db_type}/entries/{entry_id}")
async def delete_entry(db_type: str, entry_id: int):
    """Delete a specific entry from a database file and reload."""
    if db_type not in COMPILERS:
        raise HTTPException(status_code=404,
                            detail=f"Unknown database type: {db_type}")

    meta = await _get_db_meta(db_type)
    file_path = meta.get("file_path") if meta else str(_source_path(db_type))

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Source file not found")

    # Read file, remove the entry, rewrite
    with open(file_path, "r") as f:
        all_lines = f.readlines()

    # Build data-line index (skip comments/blanks)
    data_idx = 0
    new_lines = []
    removed = False
    for line in all_lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            if data_idx == entry_id:
                removed = True
                data_idx += 1
                continue
            data_idx += 1
        new_lines.append(line)

    if not removed:
        raise HTTPException(status_code=404, detail="Entry ID not found")

    with open(file_path, "w") as f:
        f.writelines(new_lines)

    # Reload
    rc = do_load(db_type, file_path)
    if rc != 0:
        raise HTTPException(status_code=500, detail="Reload after delete failed")

    return {"status": "deleted", "entry_id": entry_id, "db_type": db_type}


@db_router.post("/{db_type}/entries")
async def add_entry(db_type: str, entry: DatabaseEntry,
                    vsys: int = Query(0, ge=0, le=255)):
    """Add a single entry to a database file and perform incremental update."""
    if db_type not in COMPILERS:
        raise HTTPException(status_code=404,
                            detail=f"Unknown database type: {db_type}")

    meta = await _get_db_meta(db_type, vsys)
    file_path = meta.get("file_path") if meta else str(_source_path(db_type))
    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    # Append the new line
    with open(file_path, "a") as f:
        f.write(entry.raw_line.rstrip("\n") + "\n")

    # Write a temp file with just this one entry for incremental update
    with tempfile.NamedTemporaryFile(mode="w", delete=False,
                                     suffix=".txt") as tmp:
        tmp.write(entry.raw_line.rstrip("\n") + "\n")
        tmp_path = tmp.name

    try:
        rc = do_update(db_type, tmp_path, vsys=vsys)
        if rc != 0:
            raise HTTPException(status_code=500,
                                detail="Incremental update failed")

        from db_compiler import _load_meta as _lm
        fresh = _lm()
        key = f"{db_type}:vsys{vsys}"
        info = fresh.get(key, {})
        await _set_db_meta(
            db_type, vsys,
            info.get("entry_count", 0),
            info.get("checksum"),
            file_path,
        )

        return {
            "status": "added",
            "db_type": db_type,
            "entry_count": info.get("entry_count", 0),
        }
    finally:
        os.unlink(tmp_path)


@db_router.get("/update-status")
async def update_status():
    """Check which databases have remote feed URLs and when last updated."""
    statuses = []
    for db_type, url in FEED_URLS.items():
        meta = await _get_db_meta(db_type)
        last = meta.get("last_loaded") if meta else None
        statuses.append({
            "db_type": db_type,
            "feed_url": url,
            "last_loaded": last,
            "update_available": True,  # real impl would check ETag/Last-Modified
        })
    return {"feeds": statuses}


@db_router.post("/update-all")
async def update_all():
    """Pull latest threat feeds and reload all databases.

    In a production deployment this would fetch from FEED_URLS via HTTP,
    validate signatures, and reload.  For now we reload from the existing
    on-disk files (the feed pull would be a cron job or systemd timer).
    """
    results = []
    for db_type in sorted(COMPILERS.keys()):
        src = _source_path(db_type)
        if not src.exists():
            results.append({"db_type": db_type, "status": "skipped",
                            "reason": "no source file"})
            continue
        try:
            rc = do_load(db_type, str(src))
            status = "loaded" if rc == 0 else "failed"
        except Exception as exc:
            status = f"error: {exc}"
            rc = 1

        if rc == 0:
            from db_compiler import _load_meta as _lm
            fresh = _lm()
            key = f"{db_type}:vsys0"
            info = fresh.get(key, {})
            await _set_db_meta(
                db_type, 0,
                info.get("entry_count", 0),
                info.get("checksum"),
                str(src),
            )

        results.append({"db_type": db_type, "status": status})

    loaded = sum(1 for r in results if r["status"] == "loaded")
    return {
        "results": results,
        "total": len(results),
        "loaded": loaded,
        "failed": len(results) - loaded,
    }
