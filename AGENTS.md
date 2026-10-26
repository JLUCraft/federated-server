# AGENTS.md — federated-server

Follow the workspace rules in `../AGENTS.md`. Read [README.md](README.md) for project scope, setup, and standard validation commands.

## Documentation ownership

Keep project documentation in the root `AGENTS.md` and `README.md` only. Product content and required license files retain their existing locations. Workspace progress and evidence belong in `../TODO.md`; unresolved issues belong in `../PROBLEMS.md`. These workspace records are machine-local and are not published.

## Development boundaries

Keep sibling `union-core` and `minecraftd` checkouts available. The production entry is `federated-server`; initialization and signed host registration use its subcommands. Configuration is defined by the Rust types and command parser in `src/`. Production keys and founder authorization stay outside the repository.

Change only the affected subsystem. Use existing dependencies and build directories. Finish each batch before validation; select one validation channel and reuse successful evidence for unchanged inputs. Report skipped checks and device execution limits explicitly.
