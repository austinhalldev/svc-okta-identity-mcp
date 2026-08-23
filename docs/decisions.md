# Governance journal: svc-okta-identity-mcp

Working notes captured while building the Okta identity MCP server. The
decisions made, the alternatives declined, and why.

A companion journal exists for the previous project,
[svc-okta-log-triage](https://github.com/austinhalldev/svc-okta-log-triage),
at the same path. That project governed what data may cross a boundary:
pseudonymizing identities before they reached an external model. This
project governs a different question: what an agent is permitted to *do*,
namely tool scoping, read-only enforcement, and preventing reach into data
the agent shouldn't have.

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
