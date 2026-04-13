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

// ===================== Message constants =====================
// The encryption scheme is C = v XOR message, where v is the 32-byte scalar.
// The message must therefore be at most 32 bytes.

const MESSAGE: &str = "Message sent";
const MESSAGE_SHORT: &str = "X";
const MESSAGE_MAX: &str = "Solana32ByteTestMessage!!!!!!!!!"; // exactly 32 bytes

// ===================== Message helpers =====================

/// Encrypts a message: C = v XOR message (message must be ≤ 32 bytes).
fn encrypt_message(v: &Scalar, msg: &str) -> Vec<u8> {
    let v_bytes = v.to_bytes();
    msg.as_bytes()
        .iter()
        .enumerate()
        .map(|(i, byte)| byte ^ v_bytes[i])
        .collect()
}

/// Decrypts a ciphertext: message = C XOR v.
fn decrypt_message(ciphertext: &[u8], v: &Scalar) -> String {
    let v_bytes = v.to_bytes();
    let decrypted: Vec<u8> = ciphertext
        .iter()
        .enumerate()
        .map(|(i, byte)| byte ^ v_bytes[i])
        .collect();
    String::from_utf8_lossy(&decrypted).to_string()
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

    assert_eq!(
        computed_correct, v_point,
        "correct r must satisfy the equation"
    );
    assert_ne!(
        computed_wrong, v_point,
        "wrong r must NOT satisfy the equation"
    );
}

/// Verifies that serialising a worst-case ReceiverState fits within MAX_SIZE.
#[test]
fn test_receiver_state_max_size_is_sufficient() {
    use anchor_lang::prelude::Pubkey;
    use anchor_lang::AnchorSerialize;

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
        assert!(
            term1 > 0 && term1 < term2,
            "expected valid: term1={term1} term2={term2}"
        );
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

/// Verifies the full encrypt → ZKP → decrypt round-trip for the default message.
#[test]
fn test_message_encrypt_decrypt() {
    let v = make_scalar(10);
    let b = make_scalar(20);
    let c = make_scalar(30);
    let r = compute_response(&v, &b, &c);

    let ciphertext = encrypt_message(&v, MESSAGE);
    assert_eq!(ciphertext.len(), MESSAGE.len());

    let recovered_v = r + b * c;
    let decrypted = decrypt_message(&ciphertext, &recovered_v);
    assert_eq!(decrypted, MESSAGE);
}

/// Verifies the full encrypt → ZKP → decrypt round-trip for a 1-byte message.
#[test]
fn test_message_encrypt_decrypt_short() {
    let v = make_scalar(10);
    let b = make_scalar(20);
    let c = make_scalar(30);
    let r = compute_response(&v, &b, &c);

    let ciphertext = encrypt_message(&v, MESSAGE_SHORT);
    assert_eq!(ciphertext.len(), MESSAGE_SHORT.len());

    // Receiver recovers v = r + b·c, then decrypts
    let recovered_v = r + b * c;
    let decrypted = decrypt_message(&ciphertext, &recovered_v);
    assert_eq!(decrypted, MESSAGE_SHORT);
}

/// Verifies the full encrypt → ZKP → decrypt round-trip for a 32-byte message
/// (maximum length for the v XOR scheme).
#[test]
fn test_message_encrypt_decrypt_max() {
    assert_eq!(MESSAGE_MAX.len(), 32, "MESSAGE_MAX must be exactly 32 bytes");

    let v = make_scalar(10);
    let b = make_scalar(20);
    let c = make_scalar(30);
    let r = compute_response(&v, &b, &c);

    let ciphertext = encrypt_message(&v, MESSAGE_MAX);
    assert_eq!(ciphertext.len(), 32);

    // Receiver recovers v = r + b·c, then decrypts
    let recovered_v = r + b * c;
    let decrypted = decrypt_message(&ciphertext, &recovered_v);
    assert_eq!(decrypted, MESSAGE_MAX);
}

// ===================== BPF-dependent tests =====================
// Run with: cargo test-sbf   (or: cargo test --features test-sbf)

#[cfg(feature = "test-sbf")]
mod bpf_tests {
    use anchor_lang::{
        solana_program::{instruction::Instruction, pubkey::Pubkey, system_program},
        AccountDeserialize, InstructionData, ToAccountMetas,
    };
    use k256::{
        elliptic_curve::{ops::MulByGenerator, ScalarPrimitive},
        ProjectivePoint, Scalar,
    };
    use mollusk_svm::{program::keyed_account_for_system_program, result::Check, Mollusk};
    use solana_account::Account;
    use solana_notifications::{accounts, instruction, Delivery, State, DELIVERY_DEPOSIT};

    // ── helpers ──────────────────────────────────────────────────────────────

    fn funded(lamports: u64) -> Account {
        Account {
            lamports,
            owner: system_program::id(),
            ..Default::default()
        }
    }

    /// Converts an Anchor `#[error_code]` variant into the `ProgramError`
    /// that Mollusk's `Check::err` expects (via `.into()`).
    fn anchor_error(e: impl Into<anchor_lang::error::Error>) -> anchor_lang::prelude::ProgramError {
        e.into().into()
    }

    fn delivery_pda(program_id: &Pubkey, sender: &Pubkey, nonce: &[u8; 8]) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[b"delivery", sender.as_ref(), nonce.as_ref()], program_id)
    }

    fn vault_pda(program_id: &Pubkey, delivery: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[b"vault", delivery.as_ref()], program_id)
    }

    fn parse_delivery(result_accounts: &[(Pubkey, Account)], key: Pubkey) -> Delivery {
        let data = &result_accounts
            .iter()
            .find(|(k, _)| *k == key)
            .expect("delivery account not found")
            .1
            .data;
        Delivery::try_deserialize(&mut data.as_ref()).unwrap()
    }

    fn get_lamports(result_accounts: &[(Pubkey, Account)], key: Pubkey) -> u64 {
        result_accounts
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, a)| a.lamports)
            .unwrap_or(0)
    }

    fn get_account(result_accounts: &[(Pubkey, Account)], key: Pubkey) -> Account {
        result_accounts
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, a)| a.clone())
            .expect("account not found")
    }

    // ── existing tests (fixed to use funded accounts) ─────────────────────

    #[test]
    fn test_create_delivery_should_work() {
        let program_id = solana_notifications::id();
        let mollusk = Mollusk::new(&program_id, "solana_notifications");

        let sender = Pubkey::new_unique();
        let receiver = Pubkey::new_unique();
        let nonce = [1u8; 8];

        let v = super::make_scalar(42);
        let (vx, vy) = super::point_to_xy(&ProjectivePoint::mul_by_generator(&v));

        let (delivery_key, _) = delivery_pda(&program_id, &sender, &nonce);
        let (vault_key, _) = vault_pda(&program_id, &delivery_key);

        mollusk.process_and_validate_instruction(
            &Instruction::new_with_bytes(
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
            ),
            &[
                (sender, funded(10 * DELIVERY_DEPOSIT)),
                (delivery_key, Account::default()),
                (vault_key, Account::default()),
                keyed_account_for_system_program(),
            ],
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

        mollusk.process_and_validate_instruction(
            &Instruction::new_with_bytes(
                program_id,
                &instruction::CreateDelivery {
                    receivers: vec![receiver],
                    vx: [0u8; 32],
                    vy: [0u8; 32],
                    encrypted_message_hash: vec![],
                    a: vec![],
                    term1: 7200,
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
            ),
            &[
                (sender, funded(10 * DELIVERY_DEPOSIT)),
                (delivery_key, Account::default()),
                (vault_key, Account::default()),
                keyed_account_for_system_program(),
            ],
            &[Check::err(
                anchor_error(solana_notifications::SolanaNotificationsError::InvalidTerms).into(),
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

        mollusk.process_and_validate_instruction(
            &Instruction::new_with_bytes(
                program_id,
                &instruction::CreateDelivery {
                    receivers: vec![],
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
            ),
            &[
                (sender, funded(10 * DELIVERY_DEPOSIT)),
                (delivery_key, Account::default()),
                (vault_key, Account::default()),
                keyed_account_for_system_program(),
            ],
            &[Check::err(
                anchor_error(solana_notifications::SolanaNotificationsError::InvalidReceiversCount)
                    .into(),
            )],
        );
    }

    #[test]
    fn test_accept_should_work() {
        let program_id = solana_notifications::id();
        let mollusk = Mollusk::new(&program_id, "solana_notifications");

        let sender = Pubkey::new_unique();
        let receiver = Pubkey::new_unique();
        let nonce = [10u8; 8];

        let v = super::make_scalar(10);
        let b = super::make_scalar(20);
        let c = super::make_scalar(30);
        let (vx, vy) = super::point_to_xy(&ProjectivePoint::mul_by_generator(&v));
        let (bx, by) = super::point_to_xy(&ProjectivePoint::mul_by_generator(&b));
        let c_bytes = super::scalar_to_bytes(&c);

        let (delivery_key, _) = delivery_pda(&program_id, &sender, &nonce);
        let (vault_key, _) = vault_pda(&program_id, &delivery_key);

        let create_result = mollusk.process_instruction(
            &Instruction::new_with_bytes(
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
            ),
            &[
                (sender, funded(10 * DELIVERY_DEPOSIT)),
                (delivery_key, Account::default()),
                (vault_key, Account::default()),
                keyed_account_for_system_program(),
            ],
        );
        assert!(!create_result.program_result.is_err(), "create failed");

        let accept_result = mollusk.process_instruction(
            &Instruction::new_with_bytes(
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
            ),
            &[
                (receiver, funded(DELIVERY_DEPOSIT)),
                (
                    delivery_key,
                    get_account(&create_result.resulting_accounts, delivery_key),
                ),
            ],
        );
        assert!(!accept_result.program_result.is_err(), "accept failed");

        let delivery = parse_delivery(&accept_result.resulting_accounts, delivery_key);
        assert_eq!(delivery.receiver_states[0].state, State::Accepted);
        assert_eq!(delivery.accepted_receivers, 1);
    }

    #[test]
    fn test_finish_should_work() {
        run_finish_with_message(super::MESSAGE, [11u8; 8]);
    }

    #[test]
    fn test_cancel_should_work() {
        let program_id = solana_notifications::id();
        let mut mollusk = Mollusk::new(&program_id, "solana_notifications");
        mollusk.sysvars.clock.unix_timestamp = 0;

        let sender = Pubkey::new_unique();
        let receiver = Pubkey::new_unique();
        let nonce = [12u8; 8];

        let v = super::make_scalar(10);
        let b = super::make_scalar(20);
        let c = super::make_scalar(30);
        let (vx, vy) = super::point_to_xy(&ProjectivePoint::mul_by_generator(&v));
        let (bx, by) = super::point_to_xy(&ProjectivePoint::mul_by_generator(&b));
        let c_bytes = super::scalar_to_bytes(&c);

        let (delivery_key, _) = delivery_pda(&program_id, &sender, &nonce);
        let (vault_key, _) = vault_pda(&program_id, &delivery_key);

        // create at clock=0 → start=0, accept window [0, 3600), cancel opens at 7200
        let create_result = mollusk.process_instruction(
            &Instruction::new_with_bytes(
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
            ),
            &[
                (sender, funded(10 * DELIVERY_DEPOSIT)),
                (delivery_key, Account::default()),
                (vault_key, Account::default()),
                keyed_account_for_system_program(),
            ],
        );
        assert!(!create_result.program_result.is_err(), "create failed");

        // accept at clock=0, within term1
        let accept_result = mollusk.process_instruction(
            &Instruction::new_with_bytes(
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
            ),
            &[
                (receiver, funded(DELIVERY_DEPOSIT)),
                (
                    delivery_key,
                    get_account(&create_result.resulting_accounts, delivery_key),
                ),
            ],
        );
        assert!(!accept_result.program_result.is_err(), "accept failed");

        // advance clock past start(0) + term2(7200)
        mollusk.sysvars.clock.unix_timestamp = 8000;

        let cancel_result = mollusk.process_instruction(
            &Instruction::new_with_bytes(
                program_id,
                &instruction::Cancel {}.data(),
                accounts::CancelDelivery {
                    receiver,
                    delivery: delivery_key,
                }
                .to_account_metas(None),
            ),
            &[
                (receiver, funded(DELIVERY_DEPOSIT)),
                (
                    delivery_key,
                    get_account(&accept_result.resulting_accounts, delivery_key),
                ),
            ],
        );
        assert!(!cancel_result.program_result.is_err(), "cancel failed");

        let delivery = parse_delivery(&cancel_result.resulting_accounts, delivery_key);
        assert_eq!(delivery.receiver_states[0].state, State::Cancelled);
    }

    #[test]
    fn test_create_delivery_holds_deposit() {
        let program_id = solana_notifications::id();
        let mollusk = Mollusk::new(&program_id, "solana_notifications");

        let sender = Pubkey::new_unique();
        let receiver = Pubkey::new_unique();
        let nonce = [13u8; 8];

        let (delivery_key, _) = delivery_pda(&program_id, &sender, &nonce);
        let (vault_key, _) = vault_pda(&program_id, &delivery_key);

        let result = mollusk.process_instruction(
            &Instruction::new_with_bytes(
                program_id,
                &instruction::CreateDelivery {
                    receivers: vec![receiver],
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
            ),
            &[
                (sender, funded(10 * DELIVERY_DEPOSIT)),
                (delivery_key, Account::default()),
                (vault_key, Account::default()),
                keyed_account_for_system_program(),
            ],
        );
        assert!(!result.program_result.is_err(), "create failed");
        assert_eq!(
            get_lamports(&result.resulting_accounts, vault_key),
            DELIVERY_DEPOSIT,
            "vault should hold exactly DELIVERY_DEPOSIT after create"
        );
    }

    #[test]
    fn test_finish_releases_deposit() {
        let program_id = solana_notifications::id();
        let mollusk = Mollusk::new(&program_id, "solana_notifications");

        let sender = Pubkey::new_unique();
        let receiver = Pubkey::new_unique();
        let nonce = [14u8; 8];

        let v = super::make_scalar(10);
        let b = super::make_scalar(20);
        let c = super::make_scalar(30);
        let r = super::compute_response(&v, &b, &c);
        let (vx, vy) = super::point_to_xy(&ProjectivePoint::mul_by_generator(&v));
        let (bx, by) = super::point_to_xy(&ProjectivePoint::mul_by_generator(&b));
        let c_bytes = super::scalar_to_bytes(&c);
        let r_bytes = super::scalar_to_bytes(&r);

        let (delivery_key, _) = delivery_pda(&program_id, &sender, &nonce);
        let (vault_key, _) = vault_pda(&program_id, &delivery_key);

        let create_result = mollusk.process_instruction(
            &Instruction::new_with_bytes(
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
            ),
            &[
                (sender, funded(10 * DELIVERY_DEPOSIT)),
                (delivery_key, Account::default()),
                (vault_key, Account::default()),
                keyed_account_for_system_program(),
            ],
        );
        assert!(!create_result.program_result.is_err());
        assert_eq!(
            get_lamports(&create_result.resulting_accounts, vault_key),
            DELIVERY_DEPOSIT
        );

        let accept_result = mollusk.process_instruction(
            &Instruction::new_with_bytes(
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
            ),
            &[
                (receiver, funded(DELIVERY_DEPOSIT)),
                (
                    delivery_key,
                    get_account(&create_result.resulting_accounts, delivery_key),
                ),
            ],
        );
        assert!(!accept_result.program_result.is_err());

        let finish_result = mollusk.process_instruction(
            &Instruction::new_with_bytes(
                program_id,
                &instruction::Finish { r: r_bytes }.data(),
                accounts::FinishDelivery {
                    sender,
                    delivery: delivery_key,
                    vault: vault_key,
                    system_program: system_program::id(),
                }
                .to_account_metas(None),
            ),
            &[
                (sender, funded(DELIVERY_DEPOSIT)),
                (
                    delivery_key,
                    get_account(&accept_result.resulting_accounts, delivery_key),
                ),
                (
                    vault_key,
                    get_account(&create_result.resulting_accounts, vault_key),
                ),
                keyed_account_for_system_program(),
            ],
        );
        assert!(!finish_result.program_result.is_err(), "finish failed");
        assert_eq!(
            get_lamports(&finish_result.resulting_accounts, vault_key),
            0,
            "vault should be empty after deposit is returned to sender"
        );
    }

    #[test]
    fn test_create_delivery_fails_when_insufficient_balance() {
        let program_id = solana_notifications::id();
        let mollusk = Mollusk::new(&program_id, "solana_notifications");

        let sender = Pubkey::new_unique();
        let receiver = Pubkey::new_unique();
        let nonce = [15u8; 8];

        let (delivery_key, _) = delivery_pda(&program_id, &sender, &nonce);
        let (vault_key, _) = vault_pda(&program_id, &delivery_key);

        let result = mollusk.process_instruction(
            &Instruction::new_with_bytes(
                program_id,
                &instruction::CreateDelivery {
                    receivers: vec![receiver],
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
            ),
            &[
                (sender, funded(1_000)), // far below DELIVERY_DEPOSIT + rent
                (delivery_key, Account::default()),
                (vault_key, Account::default()),
                keyed_account_for_system_program(),
            ],
        );
        assert!(
            result.program_result.is_err(),
            "expected failure with insufficient balance"
        );
    }

    #[test]
    fn test_finish_fails_when_already_finished() {
        let program_id = solana_notifications::id();
        let mollusk = Mollusk::new(&program_id, "solana_notifications");

        let sender = Pubkey::new_unique();
        let receiver = Pubkey::new_unique();
        let nonce = [16u8; 8];

        let v = super::make_scalar(10);
        let b = super::make_scalar(20);
        let c = super::make_scalar(30);
        let r = super::compute_response(&v, &b, &c);
        let (vx, vy) = super::point_to_xy(&ProjectivePoint::mul_by_generator(&v));
        let (bx, by) = super::point_to_xy(&ProjectivePoint::mul_by_generator(&b));
        let c_bytes = super::scalar_to_bytes(&c);
        let r_bytes = super::scalar_to_bytes(&r);

        let (delivery_key, _) = delivery_pda(&program_id, &sender, &nonce);
        let (vault_key, _) = vault_pda(&program_id, &delivery_key);

        let create_result = mollusk.process_instruction(
            &Instruction::new_with_bytes(
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
            ),
            &[
                (sender, funded(10 * DELIVERY_DEPOSIT)),
                (delivery_key, Account::default()),
                (vault_key, Account::default()),
                keyed_account_for_system_program(),
            ],
        );
        assert!(!create_result.program_result.is_err());

        let accept_result = mollusk.process_instruction(
            &Instruction::new_with_bytes(
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
            ),
            &[
                (receiver, funded(DELIVERY_DEPOSIT)),
                (
                    delivery_key,
                    get_account(&create_result.resulting_accounts, delivery_key),
                ),
            ],
        );
        assert!(!accept_result.program_result.is_err());

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

        // first finish succeeds
        let finish_result = mollusk.process_instruction(
            &finish_ix,
            &[
                (sender, funded(DELIVERY_DEPOSIT)),
                (
                    delivery_key,
                    get_account(&accept_result.resulting_accounts, delivery_key),
                ),
                (
                    vault_key,
                    get_account(&create_result.resulting_accounts, vault_key),
                ),
                keyed_account_for_system_program(),
            ],
        );
        assert!(
            !finish_result.program_result.is_err(),
            "first finish should succeed"
        );

        // second finish must fail with AlreadyFinished
        mollusk.process_and_validate_instruction(
            &finish_ix,
            &[
                (sender, funded(DELIVERY_DEPOSIT)),
                (
                    delivery_key,
                    get_account(&finish_result.resulting_accounts, delivery_key),
                ),
                (
                    vault_key,
                    get_account(&finish_result.resulting_accounts, vault_key),
                ),
                keyed_account_for_system_program(),
            ],
            &[Check::err(
                anchor_error(solana_notifications::SolanaNotificationsError::AlreadyFinished)
                    .into(),
            )],
        );
    }

    #[test]
    fn test_accept_fails_after_term1_expires() {
        let program_id = solana_notifications::id();
        let mut mollusk = Mollusk::new(&program_id, "solana_notifications");
        mollusk.sysvars.clock.unix_timestamp = 0;

        let sender = Pubkey::new_unique();
        let receiver = Pubkey::new_unique();
        let nonce = [17u8; 8];

        let v = super::make_scalar(42);
        let b = super::make_scalar(20);
        let c = super::make_scalar(30);
        let (vx, vy) = super::point_to_xy(&ProjectivePoint::mul_by_generator(&v));
        let (bx, by) = super::point_to_xy(&ProjectivePoint::mul_by_generator(&b));
        let c_bytes = super::scalar_to_bytes(&c);

        let (delivery_key, _) = delivery_pda(&program_id, &sender, &nonce);
        let (vault_key, _) = vault_pda(&program_id, &delivery_key);

        // create at clock=0 → start=0, term1=3600
        let create_result = mollusk.process_instruction(
            &Instruction::new_with_bytes(
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
            ),
            &[
                (sender, funded(10 * DELIVERY_DEPOSIT)),
                (delivery_key, Account::default()),
                (vault_key, Account::default()),
                keyed_account_for_system_program(),
            ],
        );
        assert!(!create_result.program_result.is_err());

        // advance clock past start(0) + term1(3600)
        mollusk.sysvars.clock.unix_timestamp = 3601;

        mollusk.process_and_validate_instruction(
            &Instruction::new_with_bytes(
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
            ),
            &[
                (receiver, funded(DELIVERY_DEPOSIT)),
                (
                    delivery_key,
                    get_account(&create_result.resulting_accounts, delivery_key),
                ),
            ],
            &[Check::err(
                anchor_error(solana_notifications::SolanaNotificationsError::AcceptWindowExpired)
                    .into(),
            )],
        );
    }

    #[test]
    fn test_cancel_fails_before_term2_expires() {
        let program_id = solana_notifications::id();
        let mut mollusk = Mollusk::new(&program_id, "solana_notifications");
        mollusk.sysvars.clock.unix_timestamp = 0;

        let sender = Pubkey::new_unique();
        let receiver = Pubkey::new_unique();
        let nonce = [18u8; 8];

        let v = super::make_scalar(10);
        let b = super::make_scalar(20);
        let c = super::make_scalar(30);
        let (vx, vy) = super::point_to_xy(&ProjectivePoint::mul_by_generator(&v));
        let (bx, by) = super::point_to_xy(&ProjectivePoint::mul_by_generator(&b));
        let c_bytes = super::scalar_to_bytes(&c);

        let (delivery_key, _) = delivery_pda(&program_id, &sender, &nonce);
        let (vault_key, _) = vault_pda(&program_id, &delivery_key);

        let create_result = mollusk.process_instruction(
            &Instruction::new_with_bytes(
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
            ),
            &[
                (sender, funded(10 * DELIVERY_DEPOSIT)),
                (delivery_key, Account::default()),
                (vault_key, Account::default()),
                keyed_account_for_system_program(),
            ],
        );
        assert!(!create_result.program_result.is_err());

        // accept at clock=0, within term1
        let accept_result = mollusk.process_instruction(
            &Instruction::new_with_bytes(
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
            ),
            &[
                (receiver, funded(DELIVERY_DEPOSIT)),
                (
                    delivery_key,
                    get_account(&create_result.resulting_accounts, delivery_key),
                ),
            ],
        );
        assert!(!accept_result.program_result.is_err());

        // try to cancel at 7199, just before start(0)+term2(7200) → must fail
        mollusk.sysvars.clock.unix_timestamp = 7199;

        mollusk.process_and_validate_instruction(
            &Instruction::new_with_bytes(
                program_id,
                &instruction::Cancel {}.data(),
                accounts::CancelDelivery {
                    receiver,
                    delivery: delivery_key,
                }
                .to_account_metas(None),
            ),
            &[
                (receiver, funded(DELIVERY_DEPOSIT)),
                (
                    delivery_key,
                    get_account(&accept_result.resulting_accounts, delivery_key),
                ),
            ],
            &[Check::err(
                anchor_error(
                    solana_notifications::SolanaNotificationsError::CancelWindowNotReached,
                )
                .into(),
            )],
        );
    }

    /// Uses a 1-byte message; verifies the full encrypt → BPF finish → decrypt cycle.
    #[test]
    fn test_finish_should_work_short_message() {
        run_finish_with_message(super::MESSAGE_SHORT, [19u8; 8]);
    }

    /// Uses a 32-byte message (maximum for the v XOR scheme); verifies full cycle.
    #[test]
    fn test_finish_should_work_max_length_message() {
        assert_eq!(super::MESSAGE_MAX.len(), 32);
        run_finish_with_message(super::MESSAGE_MAX, [20u8; 8]);
    }

    /// Shared helper: runs create → accept → finish for a given message string,
    /// then decrypts the ciphertext off-chain and asserts it matches.
    fn run_finish_with_message(msg: &str, nonce: [u8; 8]) {
        let program_id = solana_notifications::id();
        let mollusk = Mollusk::new(&program_id, "solana_notifications");

        let sender = Pubkey::new_unique();
        let receiver = Pubkey::new_unique();

        let v = super::make_scalar(10);
        let b = super::make_scalar(20);
        let c = super::make_scalar(30);
        let r = super::compute_response(&v, &b, &c);
        let (vx, vy) = super::point_to_xy(&ProjectivePoint::mul_by_generator(&v));
        let (bx, by) = super::point_to_xy(&ProjectivePoint::mul_by_generator(&b));
        let c_bytes = super::scalar_to_bytes(&c);
        let r_bytes = super::scalar_to_bytes(&r);

        // Encrypt off-chain: C = v XOR message
        // The program stores this hash without verifying it, so we pass the
        // ciphertext itself as the hash (the receiver verifies off-chain).
        let ciphertext = super::encrypt_message(&v, msg);
        let encrypted_message_hash = ciphertext.clone();

        let (delivery_key, _) = delivery_pda(&program_id, &sender, &nonce);
        let (vault_key, _) = vault_pda(&program_id, &delivery_key);

        // create
        let create_result = mollusk.process_instruction(
            &Instruction::new_with_bytes(
                program_id,
                &instruction::CreateDelivery {
                    receivers: vec![receiver],
                    vx,
                    vy,
                    encrypted_message_hash,
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
            ),
            &[
                (sender, funded(10 * DELIVERY_DEPOSIT)),
                (delivery_key, Account::default()),
                (vault_key, Account::default()),
                keyed_account_for_system_program(),
            ],
        );
        assert!(!create_result.program_result.is_err(), "create failed");

        // accept
        let accept_result = mollusk.process_instruction(
            &Instruction::new_with_bytes(
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
            ),
            &[
                (receiver, funded(DELIVERY_DEPOSIT)),
                (delivery_key, get_account(&create_result.resulting_accounts, delivery_key)),
            ],
        );
        assert!(!accept_result.program_result.is_err(), "accept failed");

        // finish
        let finish_result = mollusk.process_instruction(
            &Instruction::new_with_bytes(
                program_id,
                &instruction::Finish { r: r_bytes }.data(),
                accounts::FinishDelivery {
                    sender,
                    delivery: delivery_key,
                    vault: vault_key,
                    system_program: system_program::id(),
                }
                .to_account_metas(None),
            ),
            &[
                (sender, funded(DELIVERY_DEPOSIT)),
                (delivery_key, get_account(&accept_result.resulting_accounts, delivery_key)),
                (vault_key, get_account(&create_result.resulting_accounts, vault_key)),
                keyed_account_for_system_program(),
            ],
        );
        assert!(!finish_result.program_result.is_err(), "finish failed");

        // Verify receiver state and decrypt the message off-chain
        let delivery = parse_delivery(&finish_result.resulting_accounts, delivery_key);
        assert_eq!(delivery.receiver_states[0].state, State::Finished);
        let r_on_chain = delivery.receiver_states[0].r;

        // Receiver: recover v = r + b·c, then decrypt C XOR v
        let r_scalar = Scalar::from(ScalarPrimitive::from_slice(&r_on_chain).unwrap());
        let c_scalar = Scalar::from(ScalarPrimitive::from_slice(&c_bytes).unwrap());
        let recovered_v = r_scalar + b * c_scalar;
        let decrypted = super::decrypt_message(&ciphertext, &recovered_v);
        assert_eq!(decrypted, msg, "decrypted message does not match original");
        println!("🔓 Decrypted message: {decrypted}");
    }
}
