# Federated Server

The JLUCraft service host for authority nodes, Minecraft connections, scoring, activity delivery, organization workflows, and AI workers.

## Setup and structure

Keep sibling `union-core` and `minecraftd` checkouts available. The production entry is `federated-server`; initialization and signed host registration use its subcommands. Configuration is defined by the Rust types and command parser in `src/`. Production keys and founder authorization stay outside the repository.

## Validation

Select one validation channel for a batch and reuse successful results for unchanged inputs. Standard commands:

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

Read [AGENTS.md](AGENTS.md) before making changes.
