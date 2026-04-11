// Tests without the BPF binary (run with `cargo test`)
// Tests that need the compiled BPF program (run with `cargo test-sbf` or
// `cargo test --features test-sbf`) are gated with #[cfg(feature = "test-sbf")].

use k256::{
    elliptic_curve::{ops::MulByGenerator, sec1::ToEncodedPoint},
    ProjectivePoint, Scalar,
};
use solana_notifications::{ReceiverState, State, MAX_Z1_SIZE, MAX_Z2_SIZE};

// ===================== Crypto helpers =====================

/// Generates a deterministic secp256k1 scalar from a seed byte.
fn make_scalar(seed: u8) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[31] = seed;
    use k256::elliptic_curve::ScalarPrimitive;
    Scalar::from(ScalarPrimitive::from_slice(&bytes).unwrap())
}

/// Returns the X and Y coordinates of a ProjectivePoint as [u8; 32] arrays.
fn point_to_xy(point: &ProjectivePoint) -> ([u8; 32], [u8; 32]) {
    let affine = point.to_affine();
    let encoded = affine.to_encoded_point(false); // uncompressed: 0x04 || x || y
    let x: [u8; 32] = encoded.x().unwrap().as_slice().try_into().unwrap();
    let y: [u8; 32] = encoded.y().unwrap().as_slice().try_into().unwrap();
    (x, y)
}

/// Computes the response r = v - b·c (mod n) so that V == G·r + B·c.
fn compute_response(v: &Scalar, b: &Scalar, c: &Scalar) -> Scalar {
    *v - b * c
}

/// Scalar to 32-byte big-endian representation.
fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
    s.to_bytes().into()
}

// ===================== Pure Rust tests (no BPF needed) =====================

/// Verifies the core ZKP identity V == G·r + B·c across many scalar combinations.
/// This is the equation checked on-chain in `finish`.
#[test]
fn test_crypto_proof_identity() {
    for seed_v in [1u8, 7, 42, 99, 200] {
        for seed_b in [2u8, 13, 55, 111] {
            for seed_c in [3u8, 17, 77] {
                let v = make_scalar(seed_v);
                let b = make_scalar(seed_b);
                let c = make_scalar(seed_c);
                let r = compute_response(&v, &b, &c);

                let v_point = ProjectivePoint::mul_by_generator(&v);
                let b_point = ProjectivePoint::mul_by_generator(&b);

                // G·r + B·c must equal V
                let computed = ProjectivePoint::mul_by_generator(&r) + b_point * c;
                assert_eq!(
                    computed, v_point,
                    "V == G·r + B·c failed for v={seed_v} b={seed_b} c={seed_c}"
                );
            }
        }
    }
}

/// Wrong r must NOT satisfy V == G·r + B·c.
#[test]
fn test_wrong_r_fails_identity() {
    let v = make_scalar(10);
    let b = make_scalar(20);
    let c = make_scalar(30);
    let r_correct = compute_response(&v, &b, &c);
    let r_wrong = make_scalar(99); // arbitrary wrong value

    let v_point = ProjectivePoint::mul_by_generator(&v);
    let b_point = ProjectivePoint::mul_by_generator(&b);

    let computed_correct = ProjectivePoint::mul_by_generator(&r_correct) + b_point * c;
    let computed_wrong = ProjectivePoint::mul_by_generator(&r_wrong) + b_point * c;

    assert_eq!(computed_correct, v_point, "correct r must satisfy the equation");
    assert_ne!(computed_wrong, v_point, "wrong r must NOT satisfy the equation");
}

/// Verifies that serialising a worst-case ReceiverState fits within MAX_SIZE.
#[test]
fn test_receiver_state_max_size_is_sufficient() {
    use anchor_lang::AnchorSerialize;
    use anchor_lang::prelude::Pubkey;

    let rs = ReceiverState {
        receiver: Pubkey::new_unique(),
        z1: vec![0xAA; MAX_Z1_SIZE],
        z2: vec![0xBB; MAX_Z2_SIZE],
        bx: [0x01; 32],
        by: [0x02; 32],
        c: [0x03; 32],
        r: [0x04; 32],
        state: State::Accepted,
    };
    let encoded = rs.try_to_vec().unwrap();
    assert!(
        encoded.len() <= ReceiverState::MAX_SIZE,
        "ReceiverState serialised {} bytes, exceeds MAX_SIZE {} bytes",
        encoded.len(),
        ReceiverState::MAX_SIZE
    );
}

/// Verifies term validation: term1 must be positive and strictly less than term2.
#[test]
fn test_term_validation_logic() {
    // These are the conditions checked in create_delivery
    let valid_cases = [(1i64, 2i64), (3600, 7200), (60, 86400)];
    for (term1, term2) in valid_cases {
        assert!(term1 > 0 && term1 < term2, "expected valid: term1={term1} term2={term2}");
    }

    let invalid_cases = [(0i64, 100i64), (7200, 3600), (100, 100), (-1, 100)];
    for (term1, term2) in invalid_cases {
        assert!(
            !(term1 > 0 && term1 < term2),
            "expected invalid: term1={term1} term2={term2}"
        );
    }
}

/// Verifies the happy-path crypto values that would be used in a full
/// create → accept → finish flow.
#[test]
fn test_finish_crypto_values_are_correct() {
    // Sender generates: secret v, commitment V = G·v
    let v = make_scalar(10);
    let v_point = ProjectivePoint::mul_by_generator(&v);
    let (vx, vy) = point_to_xy(&v_point);

    // Receiver generates: secret b, point B = G·b, challenge c
    let b = make_scalar(20);
    let b_point = ProjectivePoint::mul_by_generator(&b);
    let (bx, by) = point_to_xy(&b_point);
    let c = make_scalar(30);
    let c_bytes = scalar_to_bytes(&c);

    // Sender computes response r = v - b·c
    let r = compute_response(&v, &b, &c);
    let r_bytes = scalar_to_bytes(&r);

    // Reconstruct points from bytes (as the on-chain code does)
    use k256::{elliptic_curve::sec1::FromEncodedPoint, AffinePoint, EncodedPoint};
    let mut sec1_v = [0u8; 65];
    sec1_v[0] = 0x04;
    sec1_v[1..33].copy_from_slice(&vx);
    sec1_v[33..65].copy_from_slice(&vy);
    let v_recovered = ProjectivePoint::from(
        AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(&sec1_v).unwrap())
            .into_option()
            .unwrap(),
    );

    let mut sec1_b = [0u8; 65];
    sec1_b[0] = 0x04;
    sec1_b[1..33].copy_from_slice(&bx);
    sec1_b[33..65].copy_from_slice(&by);
    let b_recovered = ProjectivePoint::from(
        AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(&sec1_b).unwrap())
            .into_option()
            .unwrap(),
    );

    // Re-derive scalars from bytes (as on-chain code does)
    use k256::elliptic_curve::ScalarPrimitive;
    let r_scalar = Scalar::from(ScalarPrimitive::from_slice(&r_bytes).unwrap());
    let c_scalar = Scalar::from(ScalarPrimitive::from_slice(&c_bytes).unwrap());

    // Final check: G·r + B·c == V
    let computed = ProjectivePoint::mul_by_generator(&r_scalar) + b_recovered * c_scalar;
    assert_eq!(
        computed, v_recovered,
        "end-to-end crypto flow failed: V != G·r + B·c after byte round-trip"
    );
}

// ===================== BPF-dependent tests =====================
// Run with: cargo test-sbf   (or: cargo test --features test-sbf)

#[cfg(feature = "test-sbf")]
mod bpf_tests {
    use super::*;
    use anchor_lang::{
        solana_program::{instruction::Instruction, pubkey::Pubkey, system_program},
        InstructionData, ToAccountMetas,
    };
    use mollusk_svm::{result::Check, Mollusk};
    use solana_notifications::{accounts, instruction};

    fn delivery_pda(program_id: &Pubkey, sender: &Pubkey, nonce: &[u8; 8]) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[b"delivery", sender.as_ref(), nonce.as_ref()],
            program_id,
        )
    }

    fn vault_pda(program_id: &Pubkey, delivery: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[b"vault", delivery.as_ref()], program_id)
    }

    #[test]
    fn test_create_delivery_should_work() {
        let program_id = solana_notifications::id();
        let mollusk = Mollusk::new(&program_id, "solana_notifications");

        let sender = Pubkey::new_unique();
        let receiver = Pubkey::new_unique();
        let nonce = [1u8; 8];

        let v = make_scalar(42);
        let v_point = ProjectivePoint::mul_by_generator(&v);
        let (vx, vy) = point_to_xy(&v_point);

        let (delivery_key, _) = delivery_pda(&program_id, &sender, &nonce);
        let (vault_key, _) = vault_pda(&program_id, &delivery_key);

        let instruction = Instruction::new_with_bytes(
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

        mollusk.process_and_validate_instruction(
            &instruction,
            &[(sender, mollusk_svm::program::keyed_account_for_system_program())],
            &[Check::success()],
        );
    }

    #[test]
    fn test_create_delivery_fails_when_term1_gte_term2() {
        let program_id = solana_notifications::id();
        let mollusk = Mollusk::new(&program_id, "solana_notifications");

        let sender = Pubkey::new_unique();
        let receiver = Pubkey::new_unique();
        let nonce = [2u8; 8];

        let (delivery_key, _) = delivery_pda(&program_id, &sender, &nonce);
        let (vault_key, _) = vault_pda(&program_id, &delivery_key);

        let instruction = Instruction::new_with_bytes(
            program_id,
            &instruction::CreateDelivery {
                receivers: vec![receiver],
                vx: [0u8; 32],
                vy: [0u8; 32],
                encrypted_message_hash: vec![],
                a: vec![],
                term1: 7200, // term1 >= term2 → must fail
                term2: 3600,
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

        mollusk.process_and_validate_instruction(
            &instruction,
            &[(sender, mollusk_svm::program::keyed_account_for_system_program())],
            &[Check::err(
                anchor_lang::error::ErrorCode::from(
                    solana_notifications::SolanaNotificationsError::InvalidTerms,
                )
                .into(),
            )],
        );
    }

    #[test]
    fn test_create_delivery_fails_with_no_receivers() {
        let program_id = solana_notifications::id();
        let mollusk = Mollusk::new(&program_id, "solana_notifications");

        let sender = Pubkey::new_unique();
        let nonce = [3u8; 8];

        let (delivery_key, _) = delivery_pda(&program_id, &sender, &nonce);
        let (vault_key, _) = vault_pda(&program_id, &delivery_key);

        let instruction = Instruction::new_with_bytes(
            program_id,
            &instruction::CreateDelivery {
                receivers: vec![], // empty → must fail
                vx: [0u8; 32],
                vy: [0u8; 32],
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

        mollusk.process_and_validate_instruction(
            &instruction,
            &[(sender, mollusk_svm::program::keyed_account_for_system_program())],
            &[Check::err(
                anchor_lang::error::ErrorCode::from(
                    solana_notifications::SolanaNotificationsError::InvalidReceiversCount,
                )
                .into(),
            )],
        );
    }
}
