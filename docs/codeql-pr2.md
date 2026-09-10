# PR 2 CodeQL review

The check at commit `6e632a4` reported 50 alerts. The corrective changes address
the shared input boundaries rather than excluding files or disabling queries:

- Configuration XML uses defusedxml, rejects DTDs and entities, and limits raw
  fragments to 1 MiB. Normal XML escaping remains supported.
- Snapshot names and license filenames must be plain names. Store paths are
  resolved and checked for containment; existing symlinks are rejected. Invalid
  snapshot names now fail instead of silently normalizing to another name.
- Network subprocesses accept only the supported executables and validated
  argument tokens. FRR command strings reject newlines, shell escapes and pipes.
  Journal counts are converted to bounded integers and filters are validated.
- Public error responses use incident IDs instead of raw exception messages or
  exception-carried subprocess output. The server records the ID and exception
  type without logging the potentially sensitive exception text.

`defusedxml==0.7.1` is a required runtime dependency in `requirements.txt`.
Deployments using a separately maintained frozen dependency list must include it
before updating the manager.

## Alert 132: false positive

The SARIF flow for `py/clear-text-logging-sensitive-data` starts at
`d.get("trusted_ifaces", [])` and `getattr(c, "trusted_ifaces", [])` in
`opt/ffn_bmfw.py`. These are interface-name lists, not trust credentials or
secrets. `gen-nft` must emit those names in nftables interface-match rules.
Neither relay credential contents nor their paths are used by that rendering
path. `test_nft_output_contains_interface_names_not_relay_credentials` covers
the distinction. This single alert is classified as a false positive; the
query remains enabled.

## Validation

`tests/test_manager_security.py` covers normal and hostile XML, snapshot round
trips, path traversal and symlinks, command injection attempts, valid command
arguments, bounded journal reads, error redaction, and nftables output. The
suite runs in CI with the authentication and hardware API tests. Subprocesses
are mocked so the tests do not alter networking or require appliance hardware.
