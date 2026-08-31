#!/usr/bin/env python3
"""
dev_serve_ui.py -- local preview server for the FFN NGFW management WebUI.

Runs ffn_manager's FastAPI app (which serves static/index.html + the /api/*
endpoints) on 127.0.0.1 so you can iterate on the WebUI without the FPGA:
the FPGADevice falls back to simulation mode automatically.

    python dev_serve_ui.py            # -> http://127.0.0.1:8099/   (admin/admin)

NOTE: this stubs passlib's password hash to dodge a LOCAL bcrypt/passlib
version mismatch (newer `bcrypt` dropped the `__about__` attribute passlib
probes). It is a dev-preview shim ONLY -- do not use in production. The real
fix is to pin compatible versions, e.g.  pip install "bcrypt<4.1".
"""
import os
import secrets
import sys

# Isolated throwaway DB so a preview run never touches a real config.db.
os.environ.setdefault(
    "FFN_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "_ui_preview_%s.db" % secrets.token_hex(4)))

import ffn_manager as m  # noqa: E402

# Dev-only: bypass bcrypt so init_db can create the default admin locally.
m.pwd_context.hash = lambda secret, **k: "$dev-preview-stub$"

if __name__ == "__main__":
    import uvicorn
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    print("FFN NGFW WebUI preview -> http://127.0.0.1:%d/  (admin/admin)" % port)
    uvicorn.run(m.app, host="127.0.0.1", port=port, log_level="warning")
