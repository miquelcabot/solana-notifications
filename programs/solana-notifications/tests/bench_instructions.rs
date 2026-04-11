//! Compute-unit benchmarks for each instruction.
//!
//! Run with:
//!   cargo test-sbf --test bench_instructions -- --nocapture
//!
//! Each test prints the CUs consumed and asserts they stay below Solana's
//! default per-instruction limit (200 000 CU).  The `finish` instruction
//! is the most expensive because it performs secp256k1 EC arithmetic on-chain.

#![cfg(feature = "test-sbf")]

use anchor_lang::{
    solana_program::{instruction::Instruction, pubkey::Pubkey, system_program},
    InstructionData, ToAccountMetas,
};
use k256::{
    elliptic_curve::{ops::MulByGenerator, sec1::ToEncodedPoint, ScalarPrimitive},
    ProjectivePoint, Scalar,
};
use mollusk_svm::result::ProgramResult;
use mollusk_svm::{program::keyed_account_for_system_program, Mollusk};
use solana_account::Account;
use solana_notifications::{accounts, instruction, DELIVERY_DEPOSIT};

// ── helpers ──────────────────────────────────────────────────────────────────

fn make_scalar(seed: u8) -> Scalar {
    let mut b = [0u8; 32];
    b[31] = seed;
    Scalar::from(ScalarPrimitive::from_slice(&b).unwrap())
}

fn point_to_xy(p: &ProjectivePoint) -> ([u8; 32], [u8; 32]) {
    let enc = p.to_affine().to_encoded_point(false);
    let x: [u8; 32] = enc.x().unwrap().as_slice().try_into().unwrap();
    let y: [u8; 32] = enc.y().unwrap().as_slice().try_into().unwrap();
    (x, y)
}

fn scalar_bytes(s: &Scalar) -> [u8; 32] {
    s.to_bytes().into()
}

fn funded(lamports: u64) -> Account {
    Account {
        lamports,
        owner: system_program::id(),
        ..Default::default()
    }
}

fn delivery_pda(program_id: &Pubkey, sender: &Pubkey, nonce: &[u8; 8]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"delivery", sender.as_ref(), nonce.as_ref()], program_id)
}

fn vault_pda(program_id: &Pubkey, delivery: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"vault", delivery.as_ref()], program_id)
}

// create/accept/cancel: simple account operations (~5–20k CU)
// finish: includes one secp256k1_recover syscall (~25k CU) + scalar arithmetic
const MAX_CU: u64 = 200_000;

fn assert_ok(result: &ProgramResult, label: &str) {
    assert!(!result.is_err(), "{label} failed: {result:?}",);
}

// ── benchmarks ───────────────────────────────────────────────────────────────

/// Measures CUs for `create_delivery` (1 receiver).
#[test]
fn bench_create_delivery() {
    let program_id = solana_notifications::id();
    let mollusk = Mollusk::new(&program_id, "solana_notifications");

    let sender = Pubkey::new_unique();
    let receiver = Pubkey::new_unique();
    let nonce = [1u8; 8];

    let v = make_scalar(42);
    let (vx, vy) = point_to_xy(&ProjectivePoint::mul_by_generator(&v));

    let (delivery_key, _) = delivery_pda(&program_id, &sender, &nonce);
    let (vault_key, _) = vault_pda(&program_id, &delivery_key);

    let ix = Instruction::new_with_bytes(
        program_id,
        &instruction::CreateDelivery {
            receivers: vec![receiver],
            vx,
            vy,
            encrypted_message_hash: vec![0u8; 32],
            a: vec![1u8; 64],
            term1: 3600,
            term2: 7200,
            nonce,
        }
        .data(),
        accounts::CreateDelivery {
            sender,
            delivery: delivery_key,
            vault: vault_key,
            system_program: system_program::id(),
        }
        .to_account_metas(None),
    );

    let result = mollusk.process_instruction(
        &ix,
        &[
            (sender, funded(10 * DELIVERY_DEPOSIT)),
            (delivery_key, Account::default()),
            (vault_key, Account::default()),
            keyed_account_for_system_program(),
        ],
    );

    println!(
        "\n[bench] create_delivery   →  {} CU  (limit {})",
        result.compute_units_consumed, MAX_CU
    );
    assert_ok(&result.program_result, "create_delivery");
    assert!(
        result.compute_units_consumed <= MAX_CU,
        "create_delivery used {} CU, exceeds limit {}",
        result.compute_units_consumed,
        MAX_CU
    );
}

/// Measures CUs for `accept` (receiver submits cryptographic transcript).
#[test]
fn bench_accept() {
    let program_id = solana_notifications::id();
    let mollusk = Mollusk::new(&program_id, "solana_notifications");

    let sender = Pubkey::new_unique();
    let receiver = Pubkey::new_unique();
    let nonce = [2u8; 8];

    let v = make_scalar(10);
    let b = make_scalar(20);
    let c = make_scalar(30);
    let (vx, vy) = point_to_xy(&ProjectivePoint::mul_by_generator(&v));
    let (bx, by) = point_to_xy(&ProjectivePoint::mul_by_generator(&b));
    let c_bytes = scalar_bytes(&c);

    let (delivery_key, _) = delivery_pda(&program_id, &sender, &nonce);
    let (vault_key, _) = vault_pda(&program_id, &delivery_key);

    // Step 1: create the delivery so the account exists
    let create_ix = Instruction::new_with_bytes(
        program_id,
        &instruction::CreateDelivery {
            receivers: vec![receiver],
            vx,
            vy,
            encrypted_message_hash: vec![0u8; 32],
            a: vec![],
            term1: 3600,
            term2: 7200,
            nonce,
        }
        .data(),
        accounts::CreateDelivery {
            sender,
            delivery: delivery_key,
            vault: vault_key,
            system_program: system_program::id(),
        }
        .to_account_metas(None),
    );
    let create_result = mollusk.process_instruction(
        &create_ix,
        &[
            (sender, funded(10 * DELIVERY_DEPOSIT)),
            (delivery_key, Account::default()),
            (vault_key, Account::default()),
            keyed_account_for_system_program(),
        ],
    );
    assert_ok(
        &create_result.program_result,
        "create_delivery (bench_accept setup)",
    );

    let delivery_account = create_result
        .resulting_accounts
        .iter()
        .find(|(k, _)| *k == delivery_key)
        .map(|(_, a)| a.clone())
        .expect("delivery account missing after create");

    // Step 2: benchmark accept using the resulting account state
    let accept_ix = Instruction::new_with_bytes(
        program_id,
        &instruction::Accept {
            z1: vec![0xAA; 32],
            z2: vec![0xBB; 32],
            bx,
            by,
            c: c_bytes,
        }
        .data(),
        accounts::AcceptDelivery {
            receiver,
            delivery: delivery_key,
        }
        .to_account_metas(None),
    );

    let result = mollusk.process_instruction(
        &accept_ix,
        &[
            (receiver, funded(DELIVERY_DEPOSIT)),
            (delivery_key, delivery_account),
        ],
    );

    println!(
        "\n[bench] accept             →  {} CU  (limit {})",
        result.compute_units_consumed, MAX_CU
    );
    assert_ok(&result.program_result, "accept");
    assert!(
        result.compute_units_consumed <= MAX_CU,
        "accept used {} CU, exceeds limit {}",
        result.compute_units_consumed,
        MAX_CU
    );
}

/// Measures CUs for `finish` — the most expensive instruction because it runs
/// secp256k1 EC arithmetic on-chain to verify V == G·r + B·c.
#[test]
fn bench_finish() {
    let program_id = solana_notifications::id();
    let mollusk = Mollusk::new(&program_id, "solana_notifications");

    let sender = Pubkey::new_unique();
    let receiver = Pubkey::new_unique();
    let nonce = [3u8; 8];

    let v = make_scalar(10);
    let b = make_scalar(20);
    let c = make_scalar(30);
    // r = v - b·c  →  G·r + B·c == G·v == V
    let r = v - b * c;
    let (vx, vy) = point_to_xy(&ProjectivePoint::mul_by_generator(&v));
    let (bx, by) = point_to_xy(&ProjectivePoint::mul_by_generator(&b));
    let c_bytes = scalar_bytes(&c);
    let r_bytes = scalar_bytes(&r);

    let (delivery_key, _) = delivery_pda(&program_id, &sender, &nonce);
    let (vault_key, _) = vault_pda(&program_id, &delivery_key);

    // Step 1: create
    let create_ix = Instruction::new_with_bytes(
        program_id,
        &instruction::CreateDelivery {
            receivers: vec![receiver],
            vx,
            vy,
            encrypted_message_hash: vec![0u8; 32],
            a: vec![],
            term1: 3600,
            term2: 7200,
            nonce,
        }
        .data(),
        accounts::CreateDelivery {
            sender,
            delivery: delivery_key,
            vault: vault_key,
            system_program: system_program::id(),
        }
        .to_account_metas(None),
    );
    let create_result = mollusk.process_instruction(
        &create_ix,
        &[
            (sender, funded(10 * DELIVERY_DEPOSIT)),
            (delivery_key, Account::default()),
            (vault_key, Account::default()),
            keyed_account_for_system_program(),
        ],
    );
    assert_ok(
        &create_result.program_result,
        "create_delivery (bench_finish setup)",
    );

    let delivery_after_create = create_result
        .resulting_accounts
        .iter()
        .find(|(k, _)| *k == delivery_key)
        .map(|(_, a)| a.clone())
        .unwrap();
    let vault_after_create = create_result
        .resulting_accounts
        .iter()
        .find(|(k, _)| *k == vault_key)
        .map(|(_, a)| a.clone())
        .unwrap();

    // Step 2: accept
    let accept_ix = Instruction::new_with_bytes(
        program_id,
        &instruction::Accept {
            z1: vec![0xAA; 32],
            z2: vec![0xBB; 32],
            bx,
            by,
            c: c_bytes,
        }
        .data(),
        accounts::AcceptDelivery {
            receiver,
            delivery: delivery_key,
        }
        .to_account_metas(None),
    );
    let accept_result = mollusk.process_instruction(
        &accept_ix,
        &[
            (receiver, funded(DELIVERY_DEPOSIT)),
            (delivery_key, delivery_after_create),
        ],
    );
    assert_ok(&accept_result.program_result, "accept (bench_finish setup)");

    let delivery_after_accept = accept_result
        .resulting_accounts
        .iter()
        .find(|(k, _)| *k == delivery_key)
        .map(|(_, a)| a.clone())
        .unwrap();

    // Step 3: benchmark finish (with real EC verification on-chain)
    let finish_ix = Instruction::new_with_bytes(
        program_id,
        &instruction::Finish { r: r_bytes }.data(),
        accounts::FinishDelivery {
            sender,
            delivery: delivery_key,
            vault: vault_key,
            system_program: system_program::id(),
        }
        .to_account_metas(None),
    );

    let result = mollusk.process_instruction(
        &finish_ix,
        &[
            (sender, funded(DELIVERY_DEPOSIT)),
            (delivery_key, delivery_after_accept),
            (vault_key, vault_after_create),
            keyed_account_for_system_program(),
        ],
    );

    println!(
        "\n[bench] finish (EC verify) →  {} CU  (limit {})",
        result.compute_units_consumed, MAX_CU
    );
    assert_ok(&result.program_result, "finish");
    assert!(
        result.compute_units_consumed <= MAX_CU,
        "finish used {} CU, exceeds limit {}",
        result.compute_units_consumed,
        MAX_CU
    );
}

/// Measures CUs for `cancel` (receiver cancels after term2).
#[test]
fn bench_cancel() {
    let program_id = solana_notifications::id();

    // Create and accept with clock at 0
    let mut mollusk = Mollusk::new(&program_id, "solana_notifications");
    mollusk.sysvars.clock.unix_timestamp = 0;

    let sender = Pubkey::new_unique();
    let receiver = Pubkey::new_unique();
    let nonce = [4u8; 8];

    let v = make_scalar(10);
    let b = make_scalar(20);
    let c = make_scalar(30);
    let (vx, vy) = point_to_xy(&ProjectivePoint::mul_by_generator(&v));
    let (bx, by) = point_to_xy(&ProjectivePoint::mul_by_generator(&b));
    let c_bytes = scalar_bytes(&c);

    let (delivery_key, _) = delivery_pda(&program_id, &sender, &nonce);
    let (vault_key, _) = vault_pda(&program_id, &delivery_key);

    // Step 1: create (start = 0, term1 = 3600, term2 = 7200)
    let create_ix = Instruction::new_with_bytes(
        program_id,
        &instruction::CreateDelivery {
            receivers: vec![receiver],
            vx,
            vy,
            encrypted_message_hash: vec![],
            a: vec![],
            term1: 3600,
            term2: 7200,
            nonce,
        }
        .data(),
        accounts::CreateDelivery {
            sender,
            delivery: delivery_key,
            vault: vault_key,
            system_program: system_program::id(),
        }
        .to_account_metas(None),
    );
    let create_result = mollusk.process_instruction(
        &create_ix,
        &[
            (sender, funded(10 * DELIVERY_DEPOSIT)),
            (delivery_key, Account::default()),
            (vault_key, Account::default()),
            keyed_account_for_system_program(),
        ],
    );
    assert_ok(
        &create_result.program_result,
        "create_delivery (bench_cancel setup)",
    );

    let delivery_after_create = create_result
        .resulting_accounts
        .iter()
        .find(|(k, _)| *k == delivery_key)
        .map(|(_, a)| a.clone())
        .unwrap();

    // Step 2: accept (clock still at 0, within term1 = 3600)
    let accept_ix = Instruction::new_with_bytes(
        program_id,
        &instruction::Accept {
            z1: vec![],
            z2: vec![],
            bx,
            by,
            c: c_bytes,
        }
        .data(),
        accounts::AcceptDelivery {
            receiver,
            delivery: delivery_key,
        }
        .to_account_metas(None),
    );
    let accept_result = mollusk.process_instruction(
        &accept_ix,
        &[
            (receiver, funded(DELIVERY_DEPOSIT)),
            (delivery_key, delivery_after_create),
        ],
    );
    assert_ok(&accept_result.program_result, "accept (bench_cancel setup)");

    let delivery_after_accept = accept_result
        .resulting_accounts
        .iter()
        .find(|(k, _)| *k == delivery_key)
        .map(|(_, a)| a.clone())
        .unwrap();

    // Step 3: advance clock past start(0) + term2(7200) and benchmark cancel
    mollusk.sysvars.clock.unix_timestamp = 8000;

    let cancel_ix = Instruction::new_with_bytes(
        program_id,
        &instruction::Cancel {}.data(),
        accounts::CancelDelivery {
            receiver,
            delivery: delivery_key,
        }
        .to_account_metas(None),
    );

    let result = mollusk.process_instruction(
        &cancel_ix,
        &[
            (receiver, funded(DELIVERY_DEPOSIT)),
            (delivery_key, delivery_after_accept),
        ],
    );

    println!(
        "\n[bench] cancel             →  {} CU  (limit {})",
        result.compute_units_consumed, MAX_CU
    );
    assert_ok(&result.program_result, "cancel");
    assert!(
        result.compute_units_consumed <= MAX_CU,
        "cancel used {} CU, exceeds limit {}",
        result.compute_units_consumed,
        MAX_CU
    );
}

/// Measures the **total CU cost** of a complete happy-path delivery:
///   create_delivery → accept (1 receiver) → finish
///
/// On Solana each instruction is a separate transaction, so the relevant
/// metric is CU per transaction.  This test reports each step and the total.
#[test]
fn bench_full_delivery_flow() {
    let program_id = solana_notifications::id();
    let mollusk = Mollusk::new(&program_id, "solana_notifications");

    let sender = Pubkey::new_unique();
    let receiver = Pubkey::new_unique();
    let nonce = [5u8; 8];

    // Crypto setup: v (sender secret), b (receiver secret), c (challenge)
    // r = v - b·c  →  G·r + B·c = V
    let v = make_scalar(10);
    let b = make_scalar(20);
    let c = make_scalar(30);
    let r = v - b * c;
    let (vx, vy) = point_to_xy(&ProjectivePoint::mul_by_generator(&v));
    let (bx, by) = point_to_xy(&ProjectivePoint::mul_by_generator(&b));
    let c_bytes = scalar_bytes(&c);
    let r_bytes = scalar_bytes(&r);

    let (delivery_key, _) = delivery_pda(&program_id, &sender, &nonce);
    let (vault_key, _) = vault_pda(&program_id, &delivery_key);

    // ── Step 1: create_delivery ───────────────────────────────────────────────
    let create_ix = Instruction::new_with_bytes(
        program_id,
        &instruction::CreateDelivery {
            receivers: vec![receiver],
            vx,
            vy,
            encrypted_message_hash: vec![0u8; 32],
            a: vec![1u8; 64],
            term1: 3600,
            term2: 7200,
            nonce,
        }
        .data(),
        accounts::CreateDelivery {
            sender,
            delivery: delivery_key,
            vault: vault_key,
            system_program: system_program::id(),
        }
        .to_account_metas(None),
    );
    let r1 = mollusk.process_instruction(
        &create_ix,
        &[
            (sender, funded(10 * DELIVERY_DEPOSIT)),
            (delivery_key, Account::default()),
            (vault_key, Account::default()),
            keyed_account_for_system_program(),
        ],
    );
    assert_ok(&r1.program_result, "create_delivery");
    let cu_create = r1.compute_units_consumed;

    let delivery_after_create = r1
        .resulting_accounts
        .iter()
        .find(|(k, _)| *k == delivery_key)
        .map(|(_, a)| a.clone())
        .unwrap();
    let vault_after_create = r1
        .resulting_accounts
        .iter()
        .find(|(k, _)| *k == vault_key)
        .map(|(_, a)| a.clone())
        .unwrap();

    // ── Step 2: accept ────────────────────────────────────────────────────────
    let accept_ix = Instruction::new_with_bytes(
        program_id,
        &instruction::Accept {
            z1: vec![0xAA; 32],
            z2: vec![0xBB; 32],
            bx,
            by,
            c: c_bytes,
        }
        .data(),
        accounts::AcceptDelivery {
            receiver,
            delivery: delivery_key,
        }
        .to_account_metas(None),
    );
    let r2 = mollusk.process_instruction(
        &accept_ix,
        &[
            (receiver, funded(DELIVERY_DEPOSIT)),
            (delivery_key, delivery_after_create),
        ],
    );
    assert_ok(&r2.program_result, "accept");
    let cu_accept = r2.compute_units_consumed;

    let delivery_after_accept = r2
        .resulting_accounts
        .iter()
        .find(|(k, _)| *k == delivery_key)
        .map(|(_, a)| a.clone())
        .unwrap();

    // ── Step 3: finish ────────────────────────────────────────────────────────
    let finish_ix = Instruction::new_with_bytes(
        program_id,
        &instruction::Finish { r: r_bytes }.data(),
        accounts::FinishDelivery {
            sender,
            delivery: delivery_key,
            vault: vault_key,
            system_program: system_program::id(),
        }
        .to_account_metas(None),
    );
    let r3 = mollusk.process_instruction(
        &finish_ix,
        &[
            (sender, funded(DELIVERY_DEPOSIT)),
            (delivery_key, delivery_after_accept),
            (vault_key, vault_after_create),
            keyed_account_for_system_program(),
        ],
    );
    assert_ok(&r3.program_result, "finish");
    let cu_finish = r3.compute_units_consumed;

    // ── Summary ───────────────────────────────────────────────────────────────
    let cu_total = cu_create + cu_accept + cu_finish;
    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║  Full delivery flow  (1 receiver, happy path)   ║");
    println!("╠══════════════════════════════════════════════════╣");
    println!(
        "║  create_delivery  {:>10} CU                  ║",
        cu_create
    );
    println!(
        "║  accept           {:>10} CU                  ║",
        cu_accept
    );
    println!(
        "║  finish           {:>10} CU  (secp256k1)     ║",
        cu_finish
    );
    println!("╠══════════════════════════════════════════════════╣");
    println!("║  TOTAL            {:>10} CU  (3 txns)        ║", cu_total);
    println!("╚══════════════════════════════════════════════════╝");
    println!(
        "  SOL deposit locked/released: {} lamports ({:.4} SOL)",
        DELIVERY_DEPOSIT,
        DELIVERY_DEPOSIT as f64 / 1_000_000_000.0
    );
}
