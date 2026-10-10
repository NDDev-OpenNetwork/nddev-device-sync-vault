set shell := ["bash", "-euo", "pipefail", "-c"]

check:
    cargo fmt --check
    cargo test --locked --all-features --jobs 4
    cargo clippy --locked --all-targets --all-features --jobs 4 -- -D warnings
    cargo audit --deny warnings
    cargo deny --locked check licenses sources

native-acceptance:
    cargo test --locked --features development-http --lib actual_native_vault_outbox_backend_and_process_recreation -- --ignored
