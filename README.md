# Confidential Certified Notifications Program using Anchor / Solana

> This project is built with the [Anchor framework](https://www.anchor-lang.com/) on the Solana blockchain.
>
> It implements a confidential certified notification system based on asymmetric cryptography and time-locked delivery rules.

## Intro

- ⏫ This program is built on [Solana](https://solana.com/) using the [Anchor framework](https://www.anchor-lang.com/) and implements confidential certified delivery of messages using cryptographic commitments.

- 🔐 It allows a sender to securely notify one or more receivers, where receivers must accept the delivery before a deadline (`term1`) and can later claim the encrypted message within a second deadline (`term2`), ensuring message authenticity and confidentiality.

- 🧩 The cryptographic proof uses a secp256k1 zero-knowledge scheme verified on-chain via Solana's native `secp256k1_recover` syscall, achieving verification at ~25 000 compute units instead of the >1.4 M CU required by software EC arithmetic.

- 👉 Learn more about Solana programs [here](https://solana.com/docs/programs)

## Project Structure

```
solana-notifications/
├── programs/
│   └── solana-notifications/
│       ├── src/
│       │   └── lib.rs          # Program logic: instructions, accounts, errors
│       └── tests/
│           ├── test_notifications.rs   # Unit & integration tests
│           └── bench_instructions.rs  # Compute-unit benchmarks
├── app/                        # Client-side application
├── migrations/                 # Anchor migration scripts
├── Anchor.toml                 # Anchor configuration
└── Cargo.toml                  # Workspace manifest
```

### Instructions

| Instruction       | Description |
|-------------------|-------------|
| `create_delivery` | Sender creates a delivery, locking a 0.1 SOL deposit in a vault PDA |
| `accept`          | Receiver accepts within `term1`, submitting a ZKP transcript `(z1, z2, B, c)` |
| `finish`          | Sender reveals `r` after term1; on-chain verifies `V == G·r + B·c` via secp256k1 |
| `cancel`          | Receiver cancels their participation after `term2` has elapsed |

### Receiver State Machine

```
Created → Accepted → Finished
       ↘             ↗
        Rejected
Accepted → Cancelled  (after term2)
```

## Getting Started

- 🦀 This program is built with Rust. Make sure [Rust](https://www.rust-lang.org/tools/install) is installed on your system.

- ⚓ Install the [Anchor CLI](https://www.anchor-lang.com/docs/installation):

  ```sh
  cargo install --git https://github.com/coral-xyz/anchor avm --locked --force
  avm install latest
  avm use latest
  ```

- 🛠️ Install the [Solana CLI](https://solana.com/docs/intro/installation):

  ```sh
  sh -c "$(curl -sSfL https://release.solana.com/stable/install)"
  ```

Clone this repository:

```sh
git clone https://github.com/secomuib/solana-notifications.git

cd solana-notifications
```

Build the program:

```sh
anchor build
```

## Build in Debug Mode and Run Tests

During development, you can build and run pure-Rust tests (no BPF binary needed) for faster iteration:

```sh
cargo build
```

To run the pure-Rust unit tests with output:

```sh
cargo test -- --nocapture
```

To run all integration tests against the compiled BPF program:

```sh
cargo test-sbf -- --nocapture
```

To run a specific test file (e.g. `test_notifications.rs`):

```sh
cargo test-sbf --test test_notifications -- --nocapture
```

To run the compute-unit benchmarks (prints CU consumption for each instruction):

```sh
cargo test-sbf --test bench_instructions -- --nocapture
```

## Deploying to a Local Validator

Start a local Solana validator:

```sh
solana-test-validator
```

In a separate terminal, deploy the program:

```sh
anchor deploy
```

Or use Anchor's built-in local deployment (builds + deploys + runs tests):

```sh
anchor test
```

## Deploying to Devnet

Configure the Solana CLI to use devnet:

```sh
solana config set --url devnet
```

Airdrop SOL to your wallet (for deployment fees):

```sh
solana airdrop 2
```

Build and deploy:

```sh
anchor build
anchor deploy --provider.cluster devnet
```

## Interacting with the Program

The program ID on localnet is `796WZ74WaKoGxYCpxeN2Ekb38SH7ptQuM9HSZeGHyY4z`.

You can interact with the program using the Anchor client or the Solana CLI:

```sh
solana program show 796WZ74WaKoGxYCpxeN2Ekb38SH7ptQuM9HSZeGHyY4z
```

## Compute Unit Budget

Each instruction stays well within Solana's default 200 000 CU per-transaction limit. The `finish` instruction is the most expensive due to the on-chain secp256k1 proof verification:

| Instruction       | Approximate CU |
|-------------------|---------------|
| `create_delivery` | ~10 000 CU    |
| `accept`          | ~5 000 CU     |
| `finish`          | ~35 000 CU    |
| `cancel`          | ~5 000 CU     |

Run the benchmarks to get exact values on your machine:

```sh
cargo test-sbf --test bench_instructions -- --nocapture
```
