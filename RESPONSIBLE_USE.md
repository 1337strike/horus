# Responsible Use

Horus is a **defensive security tool**. It exists so that people who build and
operate LLM applications can find weaknesses in their own systems before someone
else does. Use outside that purpose is out of scope for this project and, in
most jurisdictions, likely unlawful.

## Authorised use only

Only run Horus against a system where **at least one** of these is true:

1. You own the system.
2. You have **explicit, written** permission from the owner to perform security
   testing, with a defined scope and time window.
3. It is a target explicitly designated for testing (a public bug-bounty scope
   that covers AI/LLM testing, a purpose-built CTF, or your own staging
   environment).

Written authorisation should name the systems in scope, the permitted testing
window, the rate limits you'll respect, and who to contact if something breaks.
Verbal approval from someone without authority to grant it is not authorisation.

"It's just a chatbot" is not an exception. Probing a third party's production
LLM application without permission can constitute unauthorised access, can
breach the provider's terms of service, and can cause real harm — cost, rate-limit
exhaustion, and degraded service for legitimate users.

## What this project deliberately does not ship

The framework is intentionally built so that its value is the **harness**, not an
arsenal:

- The bundled probe packs are a **small set of low-potency, publicly-documented**
  examples whose only purpose is to exercise every code path. They provide no
  meaningful capability uplift.
- The default target is an **offline mock**, so the tool does nothing to any real
  system until you deliberately configure one.
- The mutator is an **interface plus a trivial demonstration**, not a working
  attack generator. It is off by default.

If you extend Horus with your own probe packs, you are responsible for what you
put in them and for where you point them.

## Handling findings and artifacts

Run artifacts are sensitive. The SQLite database and HTML reports contain
adversarial content **and** documented weaknesses in a real system — often
someone else's.

- **Never commit them.** `*.db` and generated reports are in `.gitignore`. Keep
  them there.
- Encrypt findings at rest and in transit. Restrict who can read them to people
  who need to act on them.
- Apply a retention policy: delete client findings when the engagement's
  retention period ends.
- Keep secrets out of configs. Use the `${ENV_VAR}` syntax for all credentials.
- If you plant canary tokens, use values unique to the engagement and treat them
  as secrets.

## Disclosure

If you find a real vulnerability in someone else's system:

1. Report it privately to the owner first.
2. Follow their published disclosure policy and timelines if one exists; if not,
   a coordinated window (commonly 90 days) is a reasonable default.
3. Do not publish working exploit details for an unpatched system.
4. Do not access, exfiltrate, or retain any data beyond the minimum needed to
   demonstrate the issue.

## Reporting issues in Horus itself

If you find a security issue in this project — for example a way to make the
judge produce a false verdict, or a path that leaks credentials into logs —
please open a private security advisory on the repository rather than a public
issue.

## Interpreting results honestly

A responsibility that's easy to overlook: **don't oversell your findings.**

- An uncalibrated judge produces indicative numbers, not authoritative ones.
  Report the kappa, or report that you didn't measure it.
- Zero failures across a small number of repeats is not proof of safety. Quote
  the confidence interval.
- A run is a snapshot of one model version at one point in time. Say which.

Overstating certainty in a security report is its own kind of harm. It leads
people to trust systems they shouldn't.


## Infrastructure-agent testing (homelab only)

Horus can test agents that hold real capability — a shell, a filesystem,
network egress. This capability is modelled on offensive orchestration
frameworks, but Horus does not run offensive tools. It never executes nmap,
sqlmap, metasploit, or a shell. It inspects an agent's own action trace for the
*signatures* of those techniques and reports whether the agent could be induced
to carry them out.

Two rules apply on top of everything above:

1. **Scope is mandatory and enforced.** An `infra_agent` run refuses to start
   unless the endpoint resolves inside a declared scope. Keep the scope pinned
   to systems you own. The default posture denies cloud metadata endpoints and
   anything not explicitly allowed.

2. **Homelab only, unless you have written authorisation for a specific
   engagement.** Infrastructure testing has a larger blast radius than prompting
   a chatbot. "It resolved to a private IP" is not authorisation to test
   something that is not yours.
