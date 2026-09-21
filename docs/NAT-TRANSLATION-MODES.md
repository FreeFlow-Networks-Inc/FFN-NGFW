# NAT translation configuration

The shared policy schema drives the WebUI and `request policies nat` CLI.
All edits stage candidate configuration; activation requires Commit and a
dataplane acknowledgment.

Source translation accepts `none`, `static-ip`, `dynamic-ip`,
`dynamic-ip-and-port`, and `persistent-dynamic-ip-and-port`. Both port translation
modes offer Translated Address or Interface Address. Their selected address pool
or logical interface is stored in the corresponding source translation branch.
Interface choices come from configured Layer 3 interfaces.

Destination translation accepts `none`, `static-ip`, and `dynamic-ip`.
Dynamic IP exposes `session-distribution`: `round-robin`, `source-ip-hash`,
`ip-modulo`, `ip-hash`, or `least-sessions`. WebUI and CLI default a newly selected
dynamic destination mode to round robin. Dynamic destination settings serialize
under `dynamic-destination-translation`; legacy static destination settings retain
`destination-translation`. Existing API clients that omit `destination-type`
continue to infer static translation from their destination address.

These additional modes are configuration support, not new packet processing.
The current provider rejects activation of persistent source bindings and dynamic
destination session distribution, even for a single translated destination.
They can be stored and committed as disabled definitions. The WebUI explains
this limit; validation and Commit return explicit provider requirements.
Dynamic source IP without port translation continues to require its own allocator.

Example CLI fields (append to `request policies nat add <name>` or `edit <name>`):

```text
source-type=persistent-dynamic-ip-and-port source-interface=<configured-interface>
destination-type=dynamic-ip translated-destination=<configured-address-object> session-distribution=least-sessions
```

Switching destination translation to None through the WebUI/CLI clears its
address, port and distribution fields. Selecting static destination translation
clears distribution. API callers must submit consistent fields; mismatches fail
without modifying candidate configuration.
