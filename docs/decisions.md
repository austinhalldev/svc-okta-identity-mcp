# Governance journal: svc-okta-identity-mcp

Working notes captured while building the Okta identity MCP server. The
decisions made, the alternatives declined, and why. Entries record
decisions as they're made, ahead of and alongside implementation — a
decision logged here is a commitment the build will honor, not a
description of code that already exists.

A companion journal exists for the previous project,
[svc-okta-log-triage](https://github.com/austinhalldev/svc-okta-log-triage),
at the same path. That project governed what data may cross a boundary:
pseudonymizing identities before they reached an external model. This
project governs a different question: what an agent is permitted to *do*,
namely tool scoping, read-only enforcement, and preventing reach into data
the agent shouldn't have.

Sessions: 22 August 2026 (scaffold, decisions 1-3), and
23 August 2026 (MCP SDK v2 pin, Okta server investigation, journal
edits).

---

## Part 1: Decisions

Each of these was a real choice with an alternative that was easier.

### 1. Localhost HTTP in a container, not stdio on the host

The MCP server runs in a rootless Podman container and speaks Streamable
HTTP on a port bound to `127.0.0.1`. Claude Desktop connects over loopback.
The container mounts nothing from the host.

**The easier path:** stdio, either with the server running directly on the
host, or spawned on demand by Claude Desktop via `podman exec`.

**Why not:**
- stdio with the server running directly on the host: puts the Okta private
  key and the Okta-talking process on the host OS, a regression from
  project 1's sandbox posture.
- stdio via `podman exec` from Claude Desktop: keeps the key in the
  container, but Claude Desktop owns the process lifecycle and spawns a
  host process on demand.

**Why localhost HTTP won:** the operator controls when the agent's Okta
credential is live. Starting and stopping the container is an explicit
on/off switch for the agent's reach into the tenant, rather than the client
starting the server whenever it wants.

**On the file-access requirement, and how it's actually satisfied:** the
requirement driving this design was that the client app must not read local
files, even read-only. That's not primarily a consequence of the no-mounts
choice; Claude Desktop has no ambient filesystem access in the first place.
File access in MCP comes only from installing a server that exposes file
tools, and no filesystem or shell server is installed here, so no file tool
exists in the session at all. The no-host-mounts choice on the container is
defense in depth on top of that, not the primary control.

**Residual exposure, stated rather than glossed:** files attached to a
conversation directly are deliberate disclosure by the operator, not
ambient access by the agent. That distinction is the boundary this decision
actually draws.

### 2. The egress boundary is the tool result, not the network hop

Every tool builds its response from an explicit per-tool field allowlist.
No tool returns a raw Okta API response.

**The easier path:** returning the raw Okta API response and letting the
model pick out what it needs.

**Why this boundary and not another:** there are three trust boundaries in
this design: host to container (loopback), container to Okta (HTTPS +
DPoP, private key never leaves the container), and Claude Desktop to the
Anthropic API. The third is the one that matters for data exposure, and
it's easy to miss because it isn't in the request path from the server's
point of view. Every tool result enters the conversation, so it goes to the
Anthropic API. Real identities leave my control there.

**Consequence:** returning a whole Okta user object would ship every
profile attribute the org stores (employee ID, manager, phone, custom
attributes), regardless of what was asked. Deny-by-default on fields makes
that a deliberate choice rather than an accident, and means a new Okta
profile attribute does not silently start flowing outward.

**Contrast with project 1, and why it's a reframe rather than a repeat:**
project 1 governed what data may cross a boundary, and pseudonymization was
nearly free there because the classifier reasoned over patterns, not named
people. Here the human is asking about a specific named person, so the
identity *is* the answer, and blanket pseudonymization would defeat the
tool.

**Open question, recorded rather than resolved:** pseudonymization is
still on the table, likely selective rather than blanket, worth keeping
for bulk or enumeration tools (e.g. recent deactivations), probably not for
targeted lookups of a named individual.

### 3. Development on two machines, the credential lives on one

Development happens on either a Mac laptop or a Windows desktop, but the
Okta credential and the runtime container live only on the Mac. The Windows
machine has no `.env` and no private key, so it cannot reach the tenant.

**The easier path:** copy the private key to both machines so testing works
from either one.

**Why not:** one credential to manage, rotate, and revoke rather than two.
Testing anything that actually calls Okta happens on one known machine. If
both machines needed live access, the right answer would be a separate
keypair per machine (Okta API Services apps support multiple public keys),
so each is independently revocable, rather than copying one private key
between machines.

**Supporting detail worth recording:** `.gitattributes` pins
`* text=auto eol=lf` so Windows checkouts don't introduce CRLF line endings
that break scripts inside the Linux container.

### 4. MCP SDK: official Python SDK v2, pinned

The server is built on the official MCP Python SDK v2, pinned as
`mcp>=2,<3` in requirements. `mcp` 2.0.0 released 2026-07-28, classified
Production/Stable, and supports the 2026-07-28 MCP specification along
with every earlier revision. `mcp` 1.29.0 released the same day; the 1.x
line stays on a maintenance branch that keeps receiving critical bug
fixes and security patches. Because `pip install mcp` now resolves to
2.x, an unpinned project written against v1 breaks on the next clean
install.

**The easier path:** standalone FastMCP, or the official SDK pinned to
v1.x. Both have far more tutorials, blog posts, and community answers
matching them, because everything written before late July 2026 targets
the v1 idiom.

**Why not:** v1.x is explicitly maintenance mode — writing new code
against a superseded line this soon after its replacement shipped stable
is hard to justify. Standalone FastMCP is a third-party wrapper;
for a project whose subject is governance, an extra abstraction layer
between me and the protocol works against the point. (v2 also renamed
its own server class from `FastMCP` to `MCPServer` — the SDK's migration
guide frames this only as better reflecting the class's role in the SDK,
but the effect is that it also stops colliding, by name, with the
separate standalone FastMCP project.)

**What this costs, stated as inference rather than a measurement:** v2
shipped 2026-07-28; this decision was made in August 2026, weeks later.
My guess is that most MCP servers running in production today are still
on v1 or standalone FastMCP — not because those were chosen over v2 but
because they predate it — but that's reasoning from release timing, not
a survey; I haven't counted. The one concrete data point I actually have
is Okta's own server, cited below: it pins `<2.0.0` too. Those teams now
carry a `<2` pin and a migration ticket. Greenfield and legacy correctly
diverge here. The practical cost to me is that AI coding tools
trained on pre-v2 material default to the FastMCP idiom and will produce
code that doesn't import. Mitigation: pin explicitly, and instruct the
tool to consult current v2 documentation before writing rather than
working from memory.

**The version-management posture this reflects:** because `pip install
mcp` now resolves to 2.x, an unpinned project built for v1 breaks on the
next clean install. A team with existing v1 servers should pin `<2` and
schedule the migration deliberately rather than absorb it unplanned.
Pinning is the decision; the pin's upper bound is the part that matters.

**Corroboration, found while researching entry 5:** Okta's own reference
implementation (`github.com/okta/okta-mcp-server`) pins
`mcp[cli]>=1.28.1,<2.0.0` (`pyproject.toml:30`) — the vendor's official
server is itself still on v1, carrying exactly the `<2` pin and pending
migration this entry describes. Not a critique of that choice, and not
the reason v2 was chosen here; it's evidence that the version-management
posture above is the live industry default right now, not a hypothetical
one.

### 5. Build vs. adopt — Okta ships an MCP server

Okta ships an open-source MCP server, self-hosted and built on Okta's own
Python SDK, at `github.com/okta/okta-mcp-server`.

**What it does well, stated without hedging:** its permission model is
stronger than what this project builds. Three layers: startup pruning
removes out-of-scope tools from the registry entirely, so a tool the
token can't call never appears in `tools/list`
(`utils/scope_guard.py:207-273`, `prune_tools_by_scope`); stub tools
register in place of each pruned tool so the model still learns the
capability exists and which scope would enable it
(`utils/scope_stubs.py`); and a runtime scope re-check runs on every
call, independent of pruning (`utils/scope_guard.py:136-200`,
`require_scopes`). That's a well-designed answer to "what is this agent
permitted to do."

**What it doesn't address:** field-level egress. There is no allowlist,
no denylist, no field-selection logic anywhere in the source. The
serializer does a full `model_dump(by_alias=True, exclude_none=True,
mode="json")` of every field the model carries
(`utils/serialization.py:108-243`, specifically line 181); the only
thing it strips is transport metadata (headers, pagination wrappers),
not profile data. There is no admin-facing configuration to limit
returned fields. Whatever the Okta API returns for a user or group
object, the tool passes to the model.

**In fairness, this is a defensible position, not a defect:** a vendor
cannot know which of an org's custom profile attributes are sensitive,
so passing the object through and disclosing the exposure avoids
silently dropping a field an admin actually needs. It is
accept-and-disclose rather than minimize-by-default — a legitimate
choice for software that has to serve every Okta org's arbitrary schema,
not just mine.

**Also worth recording:** no read-only mode exists as a distinct
control. Read vs. write is determined solely by which scopes the admin
grants — grant `.manage` and the write tools go live, no separate switch
required. And no MCP tool annotations (`readOnlyHint`, `destructiveHint`)
are set anywhere across its tool registrations; access control is
entirely scope-based. That's arguably the correct posture regardless —
annotations are hints to the client, not an enforcement mechanism, so
relying on them for anything real would be the wrong control either way.

**The easier path:** adopt Okta's server, grant it only
`okta.users.read` and `okta.groups.read`, and be done. For an org
solving this problem operationally, that is probably the right call,
and this entry should say so rather than pretend the build was
necessary.

**Why build anyway:** the per-tool field allowlist is the specific
control I want to demonstrate, and it isn't something that can be
configured into theirs — it doesn't exist in their implementation.
Read-only is also a property of this architecture rather than a
consequence of scope choice: no write tool exists here to enable at all.
And this is a portfolio project whose subject is reasoning about agent
permissions and data boundaries; that isn't demonstrated by installing
someone else's software.

**Connecting the arc across both projects:** project 1 asked what data
may cross a boundary and answered with pseudonymization. Project 2 asks
what an agent may do — and Okta's server answers that well. But the
egress question doesn't disappear just because the permission question
is handled, and their answer to egress is to disclose the exposure
rather than reduce it. Pseudonymization is still the wrong tool here,
for the reason already recorded in entry 2: the identity is the answer,
so the control is field minimization, not tokenization.
