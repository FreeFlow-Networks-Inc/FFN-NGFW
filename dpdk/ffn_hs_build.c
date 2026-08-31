// SPDX-License-Identifier: GPL-2.0-or-later
// ffn_hs_build.c -- compile ffn_fastpath.hspat (+ patmeta.bin ext params) with
// libhyperscan and serialize the database to ffn_fastpath.hsdb.
//
// This is the ONE libhs-dependent build step (the "gated" step in
// ffn_fastpath_compile.py's design). It proves the compiler emits genuinely
// Hyperscan-valid patterns, and produces the .hsdb the DPDK fast path
// (ffn_scan.c) deserializes at boot.
//
//   build:  gcc -O2 -Wall ffn_hs_build.c -lhs -o ffn_hs_build
//   run:    ./ffn_hs_build <fastpath_dir>   # dir with ffn_fastpath.{hspat,patmeta.bin}
//
// patmeta.bin is authoritative for per-id flags + ext (min/max_offset); the
// .hspat supplies the pattern bodies (indexed by dense id).

#include <hs/hs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define HDR_SIZE     36
#define PATMETA_SIZE 30

#pragma pack(push, 1)
struct fp_patmeta {
    uint32_t pat_id, hs_flags, min_offset, max_offset;
    uint16_t min_length;
    uint8_t  action, severity, origin, host_confirm;
    uint16_t combo_group, name_idx, verdict, src_sid;
};
#pragma pack(pop)

static uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "open %s: ", path); perror(""); return NULL; }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(n + 1);
    if (fread(buf, 1, n, f) != (size_t)n) { fclose(f); free(buf); return NULL; }
    buf[n] = 0; fclose(f); *len = n; return buf;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <fastpath_dir>\n", argv[0]); return 2; }
    char hspat_path[512], patmeta_path[512], hsdb_path[512];
    snprintf(hspat_path,   sizeof hspat_path,   "%s/ffn_fastpath.hspat", argv[1]);
    snprintf(patmeta_path, sizeof patmeta_path, "%s/ffn_fastpath.patmeta.bin", argv[1]);
    snprintf(hsdb_path,    sizeof hsdb_path,    "%s/ffn_fastpath.hsdb", argv[1]);

    // --- patmeta (authoritative flags + ext) ---
    size_t pmlen; uint8_t *pm = read_file(patmeta_path, &pmlen);
    if (!pm) return 1;
    if (memcmp(pm, "FPPM", 4) != 0) { fprintf(stderr, "patmeta: bad magic\n"); return 1; }
    uint32_t pm_count = *(uint32_t *)(pm + 8);
    uint32_t pm_recsz = *(uint32_t *)(pm + 24);
    if (pm_recsz != PATMETA_SIZE) {
        fprintf(stderr, "patmeta record_size %u != %d (ABI drift)\n", pm_recsz, PATMETA_SIZE);
        return 1;
    }
    struct fp_patmeta *meta = (struct fp_patmeta *)(pm + HDR_SIZE);

    // --- hspat bodies, indexed by dense id ---
    size_t hslen; uint8_t *hs = read_file(hspat_path, &hslen);
    if (!hs) return 1;
    char **bodies = calloc(pm_count, sizeof(char *));
    uint32_t seen = 0;
    for (char *line = strtok((char *)hs, "\n"); line; line = strtok(NULL, "\n")) {
        if (line[0] == '#' || line[0] == 0) continue;
        char *colon = strchr(line, ':');
        if (!colon) continue;
        uint32_t id = (uint32_t)strtoul(line, NULL, 10);
        char *first = strchr(colon, '/');
        char *last  = strrchr(colon, '/');
        if (!first || last == first) continue;
        *last = 0;                              // terminate body at the last '/'
        char *body = first + 1;                 // pattern text (may contain '/')
        if (id < pm_count) { bodies[id] = strdup(body); seen++; }
    }
    if (seen != pm_count) {
        fprintf(stderr, "WARN: hspat bodies %u != patmeta count %u\n", seen, pm_count);
    }

    // --- assemble hs_compile_ext_multi arrays ---
    const char **exprs = calloc(pm_count, sizeof(char *));
    unsigned int *flags = calloc(pm_count, sizeof(unsigned));
    unsigned int *ids   = calloc(pm_count, sizeof(unsigned));
    hs_expr_ext_t **ext = calloc(pm_count, sizeof(hs_expr_ext_t *));
    for (uint32_t i = 0; i < pm_count; i++) {
        exprs[i] = bodies[i] ? bodies[i] : "";
        flags[i] = meta[i].hs_flags;
        ids[i]   = meta[i].pat_id;
        hs_expr_ext_t *e = calloc(1, sizeof(hs_expr_ext_t));
        if (meta[i].min_offset) { e->flags |= HS_EXT_FLAG_MIN_OFFSET; e->min_offset = meta[i].min_offset; }
        if (meta[i].max_offset) { e->flags |= HS_EXT_FLAG_MAX_OFFSET; e->max_offset = meta[i].max_offset; }
        if (meta[i].min_length) { e->flags |= HS_EXT_FLAG_MIN_LENGTH; e->min_length = meta[i].min_length; }
        ext[i] = e;
    }

    // The fast path uses BLOCK mode for datagrams/carved files and STREAM mode
    // for cross-packet TCP scan -- Hyperscan needs a separate DB per mode.
    (void)hsdb_path;
    struct { unsigned mode; const char *name, *suffix; } modes[] = {
        { HS_MODE_BLOCK,  "BLOCK",  "block"  },
        { HS_MODE_STREAM, "STREAM", "stream" },
    };
    int ok = 1;
    for (int m = 0; m < 2; m++) {
        hs_database_t *db = NULL; hs_compile_error_t *err = NULL;
        hs_error_t rc = hs_compile_ext_multi(exprs, flags, ids,
            (const hs_expr_ext_t *const *)ext, pm_count, modes[m].mode, NULL, &db, &err);
        if (rc != HS_SUCCESS) {
            int bad = err ? err->expression : -1;
            fprintf(stderr, "%s compile FAILED: %s (id=%d: %s)\n", modes[m].name,
                    err ? err->message : "?", bad,
                    (bad >= 0 && (uint32_t)bad < pm_count) ? exprs[bad] : "");
            hs_free_compile_error(err); ok = 0; continue;
        }
        char *bytes = NULL; size_t blen = 0;
        if (hs_serialize_database(db, &bytes, &blen) != HS_SUCCESS) {
            fprintf(stderr, "%s serialize failed\n", modes[m].name); ok = 0;
            hs_free_database(db); continue;
        }
        char path[600];
        snprintf(path, sizeof path, "%s/ffn_fastpath.%s.hsdb", argv[1], modes[m].suffix);
        FILE *of = fopen(path, "wb"); fwrite(bytes, 1, blen, of); fclose(of);
        printf("%s: %u patterns compiled + serialized %zu bytes -> %s\n",
               modes[m].name, pm_count, blen, path);
        free(bytes); hs_free_database(db);
    }
    printf("hs_version=%s\n", hs_version());
    return ok ? 0 : 1;
}
