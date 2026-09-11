# Candidate configuration objects

Objects > Addresses and Services now supports objects and static groups, scoped
to Shared or a local virtual system. Candidate permits add, edit and delete for
administrators; Running is read-only. Groups resolve local names before Shared,
reject missing members and cycles, and deletion checks XML member references.
References are deliberately conservative and may include unrelated members with
the same name. Imported dynamic groups and unsupported settings remain read-only.
Object updates preserve tags; renaming requires creating a replacement and updating
references explicitly.

The API is `/api/config/objects/{address|address-group|service|service-group}`.
GET accepts `source` and `scope`; POST creates, PUT `/{name}` updates, DELETE
`/{name}` removes, and GET `/{name}/references` lists references. Every mutation
requires the candidate SHA-256 revision returned by GET and the normal
configuration lock. Stale edits return 409, other administrators' locks return
423, and invalid addresses, ports or memberships return 422. Invalid edits leave
candidate XML unchanged. This uses the existing single-manager-worker locking
model; it does not introduce distributed locking.

These are configuration definitions. Saving or committing an object does not
create an OCTEON inspection rule. The platform's current literal packet inspection
controller and immediate routing changes remain separate from XML commit. Full
object-backed security policy compilation and transactional multi-controller
commit are still required before these definitions can drive that dataplane.
