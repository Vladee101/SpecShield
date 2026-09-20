# SpecShield documentation

**English. The Russian translation is in [`docs/`](../README.md); these files
are canonical — where the two disagree, the English is right and the Russian is
a translation bug.**

Six documents, three audiences.

| Document | For | Read it when |
|---|---|---|
| [Security Review One-Pager](Security%20Review%20One-Pager.md) | The person approving use | You have ten minutes and a decision to make |
| [Threat Model](Threat%20Model.md) | Security review | You want to know what is defended, where it is enforced, and how to check |
| [Residual Risk](Residual%20Risk.md) | The person approving use | Before you approve. It is the least flattering document here, deliberately |
| [Complete Reference](Complete%20Reference.md) | Anyone | You want every feature, every use case, and the guide in one place |
| [Desktop User Guide](Desktop%20User%20Guide.md) | Analysts and engineers | You are about to use the application |
| [User Guide](User%20Guide.md) | Engineers who prefer a terminal, or scripting CI | You want the command line |

If you only read one paragraph:

> SpecShield reduces disclosure to a commercial LLM from **"who you are plus
> what you built"** to **"what you built"**. It does not make the submission
> non-confidential. Material whose *architecture* or *business logic* is the
> secret should not go to a commercial LLM, with or without this tool.

The two user guides cover the same capabilities through different surfaces. The
application is at parity with the command line apart from `specshield report`,
which measures detection metrics against the golden corpus and is a CI tool.
Desktop guide §12 is the short list of what differs.

## Where the specifications live

The product and design documents sit in the repository root and are the source
of record for requirements and architecture:

- `Product Requirements Document (PRD).md` — requirements, threat model §4,
  success metrics §5
- `Software Design Document (SDD).md` — architecture, alias grammar §6,
  verification §7–8, vault §9, error matrix §16, security §17
- `Implementation Plan.md` — milestones and decisions
- `Design Review (PRD + SDD).md` — the review those two were revised against
- `TODO.md` — what is done, what is not, and what is known to be wrong

Where these documents and the specifications disagree, these describe **what was
built** and say so explicitly. Two such divergences exist today and both are
recorded in Residual Risk §3: there is no OS credential store, and encryption is
per-value AEAD rather than SQLCipher.

## Translation

The specifications stay English and are not translated: the source tree cites
their sections by number in roughly a hundred comments (`PRD §4.1`, `SDD §7.2`),
and a second numbered copy would drift from the first. The same reasoning keeps
CLI output, the application's labels, and every code comment in English —
[`docs/Глоссарий.md`](../Глоссарий.md) maps each term so a Russian reader knows
which English word will appear on screen.
