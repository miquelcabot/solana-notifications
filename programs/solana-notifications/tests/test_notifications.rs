//! Unified test suite for solana-notifications using LiteSVM.
//!
//! All tests (pure-Rust crypto, on-chain instructions, and CU benchmarks)
//! run with a single command:
//!
//!   anchor build && cargo test -- --nocapture
//!
//! LiteSVM loads the compiled .so binary and processes full transactions
//! (with real keypairs and signatures), closely matching validator behaviour.

use anchor_lang::{AccountDeserialize, InstructionData, ToAccountMetas};
use k256::{
    elliptic_curve::{ops::MulByGenerator, sec1::ToEncodedPoint, ScalarPrimitive},
    ProjectivePoint, Scalar,
};
use litesvm::LiteSVM;
use solana_notifications::{accounts, instruction, Delivery, State, DELIVERY_DEPOSIT};
use solana_sdk::{
    clock::Clock, instruction::Instruction, pubkey::Pubkey, signature::Keypair, signer::Signer,
    transaction::Transaction,
};

// ===================== Crypto helpers =====================

fn make_scalar(seed: u8) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[31] = seed;
    Scalar::from(ScalarPrimitive::from_slice(&bytes).unwrap())
}

fn point_to_xy(point: &ProjectivePoint) -> ([u8; 32], [u8; 32]) {
    let affine = point.to_affine();
    let encoded = affine.to_encoded_point(false);
    let x: [u8; 32] = encoded.x().unwrap().as_slice().try_into().unwrap();
    let y: [u8; 32] = encoded.y().unwrap().as_slice().try_into().unwrap();
    (x, y)
}

fn compute_response(v: &Scalar, b: &Scalar, c: &Scalar) -> Scalar {
    *v - b * c
}

fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
    s.to_bytes().into()
}

// ===================== Message helpers =====================

const MESSAGE: &str = "Message sent";
const MESSAGE_SHORT: &str = "X";
const MESSAGE_MAX: &str = "Solana32ByteTestMessage!!!!!!!!!"; // exactly 32 bytes

fn encrypt_message(v: &Scalar, msg: &str) -> Vec<u8> {
    let v_bytes = v.to_bytes();
    msg.as_bytes()
        .iter()
        .enumerate()
        .map(|(i, byte)| byte ^ v_bytes[i])
        .collect()
}

fn decrypt_message(ciphertext: &[u8], v: &Scalar) -> String {
    let v_bytes = v.to_bytes();
    let decrypted: Vec<u8> = ciphertext
        .iter()
        .enumerate()
        .map(|(i, byte)| byte ^ v_bytes[i])
        .collect();
    String::from_utf8_lossy(&decrypted).to_string()
}

// ===================== LiteSVM helpers =====================

fn setup_svm() -> LiteSVM {
    let mut svm = LiteSVM::new();
    let program_id = solana_notifications::id();
    let program_path = format!(
        "{}/../../target/deploy/solana_notifications.so",
        env!("CARGO_MANIFEST_DIR")
    );
    svm.add_program_from_file(program_id, &program_path)
        .expect("Failed to load program .so — run `anchor build` first");
    svm
}

fn delivery_pda(sender: &Pubkey, nonce: &[u8; 8]) -> (Pubkey, u8) {
    let program_id = solana_notifications::id();
    Pubkey::find_program_address(&[b"delivery", sender.as_ref(), nonce.as_ref()], &program_id)
}

fn vault_pda(delivery: &Pubkey) -> (Pubkey, u8) {
    let program_id = solana_notifications::id();
    Pubkey::find_program_address(&[b"vault", delivery.as_ref()], &program_id)
}

fn parse_delivery(svm: &LiteSVM, key: &Pubkey) -> Delivery {
    let account = svm.get_account(key).expect("delivery account not found");
    Delivery::try_deserialize(&mut account.data.as_ref()).unwrap()
}

fn send_tx(
    svm: &mut LiteSVM,
    ixs: &[Instruction],
    payer: &Keypair,
    signers: &[&Keypair],
) -> litesvm::types::TransactionMetadata {
    let blockhash = svm.latest_blockhash();
    let tx = Transaction::new_signed_with_payer(ixs, Some(&payer.pubkey()), signers, blockhash);
    svm.send_transaction(tx)
        .expect("transaction failed unexpectedly")
}

fn send_tx_expect_err(
    svm: &mut LiteSVM,
    ixs: &[Instruction],
    payer: &Keypair,
    signers: &[&Keypair],
) {
    let blockhash = svm.latest_blockhash();
    let tx = Transaction::new_signed_with_payer(ixs, Some(&payer.pubkey()), signers, blockhash);
    assert!(
        svm.send_transaction(tx).is_err(),
        "expected transaction to fail"
    );
}

/// Airdrop enough lamports for deposits + rent + fees.
fn fund(svm: &mut LiteSVM, key: &Pubkey) {
    svm.airdrop(key, 10 * DELIVERY_DEPOSIT).unwrap();
}

// ===================== Instruction builders =====================

fn create_delivery_ix(
    sender: &Pubkey,
    delivery: &Pubkey,
    vault: &Pubkey,
    receivers: Vec<Pubkey>,
    vx: [u8; 32],
    vy: [u8; 32],
    encrypted_message_hash: Vec<u8>,
    a: Vec<u8>,
    term1: i64,
    term2: i64,
    nonce: [u8; 8],
) -> Instruction {
    Instruction::new_with_bytes(
        solana_notifications::id(),
        &instruction::CreateDelivery {
            receivers,
            vx,
            vy,
            encrypted_message_hash,
            a,
            term1,
            term2,
            nonce,
        }
        .data(),
        accounts::CreateDelivery {
            sender: *sender,
            delivery: *delivery,
            vault: *vault,
            system_program: anchor_lang::system_program::ID,
        }
        .to_account_metas(None),
    )
}

fn accept_ix(
    receiver: &Pubkey,
    delivery: &Pubkey,
    z1: Vec<u8>,
    z2: Vec<u8>,
    bx: [u8; 32],
    by: [u8; 32],
    c: [u8; 32],
) -> Instruction {
    Instruction::new_with_bytes(
        solana_notifications::id(),
        &instruction::Accept { z1, z2, bx, by, c }.data(),
        accounts::AcceptDelivery {
            receiver: *receiver,
            delivery: *delivery,
        }
        .to_account_metas(None),
    )
}

fn finish_ix(
    sender: &Pubkey,
    delivery: &Pubkey,
    vault: &Pubkey,
    receiver: Pubkey,
    r: [u8; 32],
) -> Instruction {
    Instruction::new_with_bytes(
        solana_notifications::id(),
        &instruction::Finish { receiver, r }.data(),
        accounts::FinishDelivery {
            sender: *sender,
            delivery: *delivery,
            vault: *vault,
            system_program: anchor_lang::system_program::ID,
        }
        .to_account_metas(None),
    )
}

fn cancel_ix(receiver: &Pubkey, delivery: &Pubkey) -> Instruction {
    Instruction::new_with_bytes(
        solana_notifications::id(),
        &instruction::Cancel {}.data(),
        accounts::CancelDelivery {
            receiver: *receiver,
            delivery: *delivery,
        }
        .to_account_metas(None),
    )
}

// ===================== Pure Rust tests (no SVM needed) =====================

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

                let computed = ProjectivePoint::mul_by_generator(&r) + b_point * c;
                assert_eq!(
                    computed, v_point,
                    "V == G·r + B·c failed for v={seed_v} b={seed_b} c={seed_c}"
                );
            }
        }
    }
}

#[test]
fn test_wrong_r_fails_identity() {
    let v = make_scalar(10);
    let b = make_scalar(20);
    let c = make_scalar(30);
    let r_correct = compute_response(&v, &b, &c);
    let r_wrong = make_scalar(99);

    let v_point = ProjectivePoint::mul_by_generator(&v);
    let b_point = ProjectivePoint::mul_by_generator(&b);

    let computed_correct = ProjectivePoint::mul_by_generator(&r_correct) + b_point * c;
    let computed_wrong = ProjectivePoint::mul_by_generator(&r_wrong) + b_point * c;

    assert_eq!(computed_correct, v_point);
    assert_ne!(computed_wrong, v_point);
}

#[test]
fn test_receiver_state_max_size_is_sufficient() {
    use anchor_lang::prelude::Pubkey;
    use anchor_lang::AnchorSerialize;
    use solana_notifications::{ReceiverState, MAX_Z1_SIZE, MAX_Z2_SIZE};

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
        encoded.len() <= solana_notifications::ReceiverState::MAX_SIZE,
        "ReceiverState serialised {} bytes, exceeds MAX_SIZE {} bytes",
        encoded.len(),
        solana_notifications::ReceiverState::MAX_SIZE
    );
}

#[test]
fn test_term_validation_logic() {
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

#[test]
fn test_finish_crypto_values_are_correct() {
    let v = make_scalar(10);
    let v_point = ProjectivePoint::mul_by_generator(&v);
    let (vx, vy) = point_to_xy(&v_point);

    let b = make_scalar(20);
    let b_point = ProjectivePoint::mul_by_generator(&b);
    let (bx, by) = point_to_xy(&b_point);
    let c = make_scalar(30);
    let c_bytes = scalar_to_bytes(&c);

    let r = compute_response(&v, &b, &c);
    let r_bytes = scalar_to_bytes(&r);

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

    let r_scalar = Scalar::from(ScalarPrimitive::from_slice(&r_bytes).unwrap());
    let c_scalar = Scalar::from(ScalarPrimitive::from_slice(&c_bytes).unwrap());

    let computed = ProjectivePoint::mul_by_generator(&r_scalar) + b_recovered * c_scalar;
    assert_eq!(
        computed, v_recovered,
        "end-to-end crypto flow failed: V != G·r + B·c after byte round-trip"
    );
}

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

#[test]
fn test_message_encrypt_decrypt_short() {
    let v = make_scalar(10);
    let b = make_scalar(20);
    let c = make_scalar(30);
    let r = compute_response(&v, &b, &c);

    let ciphertext = encrypt_message(&v, MESSAGE_SHORT);
    assert_eq!(ciphertext.len(), MESSAGE_SHORT.len());

    let recovered_v = r + b * c;
    let decrypted = decrypt_message(&ciphertext, &recovered_v);
    assert_eq!(decrypted, MESSAGE_SHORT);
}

#[test]
fn test_message_encrypt_decrypt_max() {
    assert_eq!(
        MESSAGE_MAX.len(),
        32,
        "MESSAGE_MAX must be exactly 32 bytes"
    );

    let v = make_scalar(10);
    let b = make_scalar(20);
    let c = make_scalar(30);
    let r = compute_response(&v, &b, &c);

    let ciphertext = encrypt_message(&v, MESSAGE_MAX);
    assert_eq!(ciphertext.len(), 32);

    let recovered_v = r + b * c;
    let decrypted = decrypt_message(&ciphertext, &recovered_v);
    assert_eq!(decrypted, MESSAGE_MAX);
}

// ===================== On-chain tests (LiteSVM) =====================

#[test]
fn test_create_delivery_should_work() {
    let mut svm = setup_svm();

    let sender = Keypair::new();
    let receiver = Pubkey::new_unique();
    let nonce = [1u8; 8];
    fund(&mut svm, &sender.pubkey());

    let v = make_scalar(42);
    let (vx, vy) = point_to_xy(&ProjectivePoint::mul_by_generator(&v));

    let (delivery_key, _) = delivery_pda(&sender.pubkey(), &nonce);
    let (vault_key, _) = vault_pda(&delivery_key);

    let ix = create_delivery_ix(
        &sender.pubkey(),
        &delivery_key,
        &vault_key,
        vec![receiver],
        vx,
        vy,
        vec![0u8; 32],
        vec![1u8; 64],
        3600,
        7200,
        nonce,
    );

    send_tx(&mut svm, &[ix], &sender, &[&sender]);

    let delivery = parse_delivery(&svm, &delivery_key);
    assert_eq!(delivery.sender, sender.pubkey());
    assert_eq!(delivery.receiver_states.len(), 1);
    assert_eq!(delivery.receiver_states[0].receiver, receiver);
    assert_eq!(delivery.receiver_states[0].state, State::Created);
}

#[test]
fn test_create_delivery_fails_when_term1_gte_term2() {
    let mut svm = setup_svm();

    let sender = Keypair::new();
    let receiver = Pubkey::new_unique();
    let nonce = [2u8; 8];
    fund(&mut svm, &sender.pubkey());

    let (delivery_key, _) = delivery_pda(&sender.pubkey(), &nonce);
    let (vault_key, _) = vault_pda(&delivery_key);

    let ix = create_delivery_ix(
        &sender.pubkey(),
        &delivery_key,
        &vault_key,
        vec![receiver],
        [0u8; 32],
        [0u8; 32],
        vec![],
        vec![],
        7200, // term1 > term2 → invalid
        3600,
        nonce,
    );

    send_tx_expect_err(&mut svm, &[ix], &sender, &[&sender]);
}

#[test]
fn test_create_delivery_fails_with_no_receivers() {
    let mut svm = setup_svm();

    let sender = Keypair::new();
    let nonce = [3u8; 8];
    fund(&mut svm, &sender.pubkey());

    let (delivery_key, _) = delivery_pda(&sender.pubkey(), &nonce);
    let (vault_key, _) = vault_pda(&delivery_key);

    let ix = create_delivery_ix(
        &sender.pubkey(),
        &delivery_key,
        &vault_key,
        vec![], // no receivers → invalid
        [0u8; 32],
        [0u8; 32],
        vec![],
        vec![],
        3600,
        7200,
        nonce,
    );

    send_tx_expect_err(&mut svm, &[ix], &sender, &[&sender]);
}

#[test]
fn test_accept_should_work() {
    let mut svm = setup_svm();

    let sender = Keypair::new();
    let receiver = Keypair::new();
    let nonce = [10u8; 8];
    fund(&mut svm, &sender.pubkey());
    fund(&mut svm, &receiver.pubkey());

    let v = make_scalar(10);
    let b = make_scalar(20);
    let c = make_scalar(30);
    let (vx, vy) = point_to_xy(&ProjectivePoint::mul_by_generator(&v));
    let (bx, by) = point_to_xy(&ProjectivePoint::mul_by_generator(&b));
    let c_bytes = scalar_to_bytes(&c);

    let (delivery_key, _) = delivery_pda(&sender.pubkey(), &nonce);
    let (vault_key, _) = vault_pda(&delivery_key);

    // create
    let create_ix = create_delivery_ix(
        &sender.pubkey(),
        &delivery_key,
        &vault_key,
        vec![receiver.pubkey()],
        vx,
        vy,
        vec![0u8; 32],
        vec![],
        3600,
        7200,
        nonce,
    );
    send_tx(&mut svm, &[create_ix], &sender, &[&sender]);

    // accept
    let accept = accept_ix(
        &receiver.pubkey(),
        &delivery_key,
        vec![0xAA; 32],
        vec![0xBB; 32],
        bx,
        by,
        c_bytes,
    );
    send_tx(&mut svm, &[accept], &receiver, &[&receiver]);

    let delivery = parse_delivery(&svm, &delivery_key);
    assert_eq!(delivery.receiver_states[0].state, State::Accepted);
    assert_eq!(delivery.accepted_receivers, 1);
}

#[test]
fn test_finish_should_work() {
    run_finish_with_message(MESSAGE, [11u8; 8]);
}

#[test]
fn test_finish_should_work_short_message() {
    run_finish_with_message(MESSAGE_SHORT, [19u8; 8]);
}

#[test]
fn test_finish_should_work_max_length_message() {
    assert_eq!(MESSAGE_MAX.len(), 32);
    run_finish_with_message(MESSAGE_MAX, [20u8; 8]);
}

fn run_finish_with_message(msg: &str, nonce: [u8; 8]) {
    let mut svm = setup_svm();

    let sender = Keypair::new();
    let receiver = Keypair::new();
    fund(&mut svm, &sender.pubkey());
    fund(&mut svm, &receiver.pubkey());

    let v = make_scalar(10);
    let b = make_scalar(20);
    let c = make_scalar(30);
    let r = compute_response(&v, &b, &c);
    let (vx, vy) = point_to_xy(&ProjectivePoint::mul_by_generator(&v));
    let (bx, by) = point_to_xy(&ProjectivePoint::mul_by_generator(&b));
    let c_bytes = scalar_to_bytes(&c);
    let r_bytes = scalar_to_bytes(&r);

    let ciphertext = encrypt_message(&v, msg);
    let encrypted_message_hash = ciphertext.clone();

    let (delivery_key, _) = delivery_pda(&sender.pubkey(), &nonce);
    let (vault_key, _) = vault_pda(&delivery_key);

    // create
    let create_ix = create_delivery_ix(
        &sender.pubkey(),
        &delivery_key,
        &vault_key,
        vec![receiver.pubkey()],
        vx,
        vy,
        encrypted_message_hash,
        vec![],
        3600,
        7200,
        nonce,
    );
    send_tx(&mut svm, &[create_ix], &sender, &[&sender]);

    // accept
    let accept = accept_ix(
        &receiver.pubkey(),
        &delivery_key,
        vec![0xAA; 32],
        vec![0xBB; 32],
        bx,
        by,
        c_bytes,
    );
    send_tx(&mut svm, &[accept], &receiver, &[&receiver]);

    // finish
    let finish = finish_ix(
        &sender.pubkey(),
        &delivery_key,
        &vault_key,
        receiver.pubkey(),
        r_bytes,
    );
    send_tx(&mut svm, &[finish], &sender, &[&sender]);

    // Verify state and decrypt
    let delivery = parse_delivery(&svm, &delivery_key);
    assert_eq!(delivery.receiver_states[0].state, State::Finished);
    let r_on_chain = delivery.receiver_states[0].r;

    let r_scalar = Scalar::from(ScalarPrimitive::from_slice(&r_on_chain).unwrap());
    let c_scalar = Scalar::from(ScalarPrimitive::from_slice(&c_bytes).unwrap());
    let recovered_v = r_scalar + b * c_scalar;
    let decrypted = decrypt_message(&ciphertext, &recovered_v);
    assert_eq!(decrypted, msg, "decrypted message does not match original");
    println!("Decrypted message: {decrypted}");
}

#[test]
fn test_cancel_should_work() {
    let mut svm = setup_svm();

    let sender = Keypair::new();
    let receiver = Keypair::new();
    let nonce = [12u8; 8];
    fund(&mut svm, &sender.pubkey());
    fund(&mut svm, &receiver.pubkey());

    let v = make_scalar(10);
    let b = make_scalar(20);
    let c = make_scalar(30);
    let (vx, vy) = point_to_xy(&ProjectivePoint::mul_by_generator(&v));
    let (bx, by) = point_to_xy(&ProjectivePoint::mul_by_generator(&b));
    let c_bytes = scalar_to_bytes(&c);

    let (delivery_key, _) = delivery_pda(&sender.pubkey(), &nonce);
    let (vault_key, _) = vault_pda(&delivery_key);

    // create
    let create_ix = create_delivery_ix(
        &sender.pubkey(),
        &delivery_key,
        &vault_key,
        vec![receiver.pubkey()],
        vx,
        vy,
        vec![],
        vec![],
        3600,
        7200,
        nonce,
    );
    send_tx(&mut svm, &[create_ix], &sender, &[&sender]);

    // accept
    let accept = accept_ix(
        &receiver.pubkey(),
        &delivery_key,
        vec![],
        vec![],
        bx,
        by,
        c_bytes,
    );
    send_tx(&mut svm, &[accept], &receiver, &[&receiver]);

    // advance clock past start + term2
    let mut clock: Clock = svm.get_sysvar();
    clock.unix_timestamp += 8000;
    svm.set_sysvar(&clock);

    // cancel
    let cancel = cancel_ix(&receiver.pubkey(), &delivery_key);
    send_tx(&mut svm, &[cancel], &receiver, &[&receiver]);

    let delivery = parse_delivery(&svm, &delivery_key);
    assert_eq!(delivery.receiver_states[0].state, State::Cancelled);
}

#[test]
fn test_create_delivery_holds_deposit() {
    let mut svm = setup_svm();

    let sender = Keypair::new();
    let receiver = Pubkey::new_unique();
    let nonce = [13u8; 8];
    fund(&mut svm, &sender.pubkey());

    let (delivery_key, _) = delivery_pda(&sender.pubkey(), &nonce);
    let (vault_key, _) = vault_pda(&delivery_key);

    let ix = create_delivery_ix(
        &sender.pubkey(),
        &delivery_key,
        &vault_key,
        vec![receiver],
        [0u8; 32],
        [0u8; 32],
        vec![],
        vec![],
        3600,
        7200,
        nonce,
    );
    send_tx(&mut svm, &[ix], &sender, &[&sender]);

    let vault_account = svm
        .get_account(&vault_key)
        .expect("vault account not found");
    assert_eq!(
        vault_account.lamports, DELIVERY_DEPOSIT,
        "vault should hold exactly DELIVERY_DEPOSIT after create"
    );
}

#[test]
fn test_finish_releases_deposit() {
    let mut svm = setup_svm();

    let sender = Keypair::new();
    let receiver = Keypair::new();
    let nonce = [14u8; 8];
    fund(&mut svm, &sender.pubkey());
    fund(&mut svm, &receiver.pubkey());

    let v = make_scalar(10);
    let b = make_scalar(20);
    let c = make_scalar(30);
    let r = compute_response(&v, &b, &c);
    let (vx, vy) = point_to_xy(&ProjectivePoint::mul_by_generator(&v));
    let (bx, by) = point_to_xy(&ProjectivePoint::mul_by_generator(&b));
    let c_bytes = scalar_to_bytes(&c);
    let r_bytes = scalar_to_bytes(&r);

    let (delivery_key, _) = delivery_pda(&sender.pubkey(), &nonce);
    let (vault_key, _) = vault_pda(&delivery_key);

    // create
    let create_ix = create_delivery_ix(
        &sender.pubkey(),
        &delivery_key,
        &vault_key,
        vec![receiver.pubkey()],
        vx,
        vy,
        vec![0u8; 32],
        vec![],
        3600,
        7200,
        nonce,
    );
    send_tx(&mut svm, &[create_ix], &sender, &[&sender]);
    assert_eq!(
        svm.get_account(&vault_key).unwrap().lamports,
        DELIVERY_DEPOSIT,
    );

    // accept
    let accept = accept_ix(
        &receiver.pubkey(),
        &delivery_key,
        vec![0xAA; 32],
        vec![0xBB; 32],
        bx,
        by,
        c_bytes,
    );
    send_tx(&mut svm, &[accept], &receiver, &[&receiver]);

    // finish
    let finish = finish_ix(
        &sender.pubkey(),
        &delivery_key,
        &vault_key,
        receiver.pubkey(),
        r_bytes,
    );
    send_tx(&mut svm, &[finish], &sender, &[&sender]);

    // vault should be empty (or gone)
    let vault_lamports = svm.get_account(&vault_key).map(|a| a.lamports).unwrap_or(0);
    assert_eq!(
        vault_lamports, 0,
        "vault should be empty after deposit is returned to sender"
    );
}

#[test]
fn test_create_delivery_fails_when_insufficient_balance() {
    let mut svm = setup_svm();

    let sender = Keypair::new();
    let receiver = Pubkey::new_unique();
    let nonce = [15u8; 8];
    // Give sender only 1000 lamports — far below DELIVERY_DEPOSIT + rent
    svm.airdrop(&sender.pubkey(), 1_000).unwrap();

    let (delivery_key, _) = delivery_pda(&sender.pubkey(), &nonce);
    let (vault_key, _) = vault_pda(&delivery_key);

    let ix = create_delivery_ix(
        &sender.pubkey(),
        &delivery_key,
        &vault_key,
        vec![receiver],
        [0u8; 32],
        [0u8; 32],
        vec![],
        vec![],
        3600,
        7200,
        nonce,
    );

    send_tx_expect_err(&mut svm, &[ix], &sender, &[&sender]);
}

#[test]
fn test_finish_fails_when_already_finished() {
    let mut svm = setup_svm();

    let sender = Keypair::new();
    let receiver = Keypair::new();
    let nonce = [16u8; 8];
    fund(&mut svm, &sender.pubkey());
    fund(&mut svm, &receiver.pubkey());

    let v = make_scalar(10);
    let b = make_scalar(20);
    let c = make_scalar(30);
    let r = compute_response(&v, &b, &c);
    let (vx, vy) = point_to_xy(&ProjectivePoint::mul_by_generator(&v));
    let (bx, by) = point_to_xy(&ProjectivePoint::mul_by_generator(&b));
    let c_bytes = scalar_to_bytes(&c);
    let r_bytes = scalar_to_bytes(&r);

    let (delivery_key, _) = delivery_pda(&sender.pubkey(), &nonce);
    let (vault_key, _) = vault_pda(&delivery_key);

    // create
    let create_ix = create_delivery_ix(
        &sender.pubkey(),
        &delivery_key,
        &vault_key,
        vec![receiver.pubkey()],
        vx,
        vy,
        vec![0u8; 32],
        vec![],
        3600,
        7200,
        nonce,
    );
    send_tx(&mut svm, &[create_ix], &sender, &[&sender]);

    // accept
    let accept = accept_ix(
        &receiver.pubkey(),
        &delivery_key,
        vec![0xAA; 32],
        vec![0xBB; 32],
        bx,
        by,
        c_bytes,
    );
    send_tx(&mut svm, &[accept], &receiver, &[&receiver]);

    // first finish — succeeds
    let finish = finish_ix(
        &sender.pubkey(),
        &delivery_key,
        &vault_key,
        receiver.pubkey(),
        r_bytes,
    );
    send_tx(&mut svm, &[finish], &sender, &[&sender]);

    // second finish — must fail (AlreadyFinished)
    let finish2 = finish_ix(
        &sender.pubkey(),
        &delivery_key,
        &vault_key,
        receiver.pubkey(),
        r_bytes,
    );
    send_tx_expect_err(&mut svm, &[finish2], &sender, &[&sender]);
}

#[test]
fn test_accept_fails_after_term1_expires() {
    let mut svm = setup_svm();

    let sender = Keypair::new();
    let receiver = Keypair::new();
    let nonce = [17u8; 8];
    fund(&mut svm, &sender.pubkey());
    fund(&mut svm, &receiver.pubkey());

    let v = make_scalar(42);
    let b = make_scalar(20);
    let c = make_scalar(30);
    let (vx, vy) = point_to_xy(&ProjectivePoint::mul_by_generator(&v));
    let (bx, by) = point_to_xy(&ProjectivePoint::mul_by_generator(&b));
    let c_bytes = scalar_to_bytes(&c);

    let (delivery_key, _) = delivery_pda(&sender.pubkey(), &nonce);
    let (vault_key, _) = vault_pda(&delivery_key);

    // create
    let create_ix = create_delivery_ix(
        &sender.pubkey(),
        &delivery_key,
        &vault_key,
        vec![receiver.pubkey()],
        vx,
        vy,
        vec![],
        vec![],
        3600,
        7200,
        nonce,
    );
    send_tx(&mut svm, &[create_ix], &sender, &[&sender]);

    // advance clock past start + term1
    let mut clock: Clock = svm.get_sysvar();
    clock.unix_timestamp += 3601;
    svm.set_sysvar(&clock);

    // accept should fail
    let accept = accept_ix(
        &receiver.pubkey(),
        &delivery_key,
        vec![0xAA; 32],
        vec![0xBB; 32],
        bx,
        by,
        c_bytes,
    );
    send_tx_expect_err(&mut svm, &[accept], &receiver, &[&receiver]);
}

#[test]
fn test_cancel_fails_before_term2_expires() {
    let mut svm = setup_svm();

    let sender = Keypair::new();
    let receiver = Keypair::new();
    let nonce = [18u8; 8];
    fund(&mut svm, &sender.pubkey());
    fund(&mut svm, &receiver.pubkey());

    let v = make_scalar(10);
    let b = make_scalar(20);
    let c = make_scalar(30);
    let (vx, vy) = point_to_xy(&ProjectivePoint::mul_by_generator(&v));
    let (bx, by) = point_to_xy(&ProjectivePoint::mul_by_generator(&b));
    let c_bytes = scalar_to_bytes(&c);

    let (delivery_key, _) = delivery_pda(&sender.pubkey(), &nonce);
    let (vault_key, _) = vault_pda(&delivery_key);

    // create
    let create_ix = create_delivery_ix(
        &sender.pubkey(),
        &delivery_key,
        &vault_key,
        vec![receiver.pubkey()],
        vx,
        vy,
        vec![],
        vec![],
        3600,
        7200,
        nonce,
    );
    send_tx(&mut svm, &[create_ix], &sender, &[&sender]);

    // accept
    let accept = accept_ix(
        &receiver.pubkey(),
        &delivery_key,
        vec![],
        vec![],
        bx,
        by,
        c_bytes,
    );
    send_tx(&mut svm, &[accept], &receiver, &[&receiver]);

    // advance clock to just before start + term2 (7199 seconds, not enough)
    let mut clock: Clock = svm.get_sysvar();
    clock.unix_timestamp += 7199;
    svm.set_sysvar(&clock);

    // cancel should fail — too early
    let cancel = cancel_ix(&receiver.pubkey(), &delivery_key);
    send_tx_expect_err(&mut svm, &[cancel], &receiver, &[&receiver]);
}

// ===================== CU Benchmarks =====================

const MAX_CU: u64 = 200_000;

#[test]
fn bench_create_delivery() {
    let mut svm = setup_svm();

    let sender = Keypair::new();
    let receiver = Pubkey::new_unique();
    let nonce = [101u8; 8];
    fund(&mut svm, &sender.pubkey());

    let v = make_scalar(42);
    let (vx, vy) = point_to_xy(&ProjectivePoint::mul_by_generator(&v));

    let (delivery_key, _) = delivery_pda(&sender.pubkey(), &nonce);
    let (vault_key, _) = vault_pda(&delivery_key);

    let ix = create_delivery_ix(
        &sender.pubkey(),
        &delivery_key,
        &vault_key,
        vec![receiver],
        vx,
        vy,
        vec![0u8; 32],
        vec![1u8; 64],
        3600,
        7200,
        nonce,
    );

    let metadata = send_tx(&mut svm, &[ix], &sender, &[&sender]);
    println!(
        "\n[bench] create_delivery   →  {} CU  (limit {})",
        metadata.compute_units_consumed, MAX_CU
    );
    assert!(
        metadata.compute_units_consumed <= MAX_CU,
        "create_delivery used {} CU, exceeds limit {}",
        metadata.compute_units_consumed,
        MAX_CU
    );
}

#[test]
fn bench_accept() {
    let mut svm = setup_svm();

    let sender = Keypair::new();
    let receiver = Keypair::new();
    let nonce = [102u8; 8];
    fund(&mut svm, &sender.pubkey());
    fund(&mut svm, &receiver.pubkey());

    let v = make_scalar(10);
    let b = make_scalar(20);
    let c = make_scalar(30);
    let (vx, vy) = point_to_xy(&ProjectivePoint::mul_by_generator(&v));
    let (bx, by) = point_to_xy(&ProjectivePoint::mul_by_generator(&b));
    let c_bytes = scalar_to_bytes(&c);

    let (delivery_key, _) = delivery_pda(&sender.pubkey(), &nonce);
    let (vault_key, _) = vault_pda(&delivery_key);

    let create_ix = create_delivery_ix(
        &sender.pubkey(),
        &delivery_key,
        &vault_key,
        vec![receiver.pubkey()],
        vx,
        vy,
        vec![0u8; 32],
        vec![],
        3600,
        7200,
        nonce,
    );
    send_tx(&mut svm, &[create_ix], &sender, &[&sender]);

    let accept = accept_ix(
        &receiver.pubkey(),
        &delivery_key,
        vec![0xAA; 32],
        vec![0xBB; 32],
        bx,
        by,
        c_bytes,
    );
    let metadata = send_tx(&mut svm, &[accept], &receiver, &[&receiver]);
    println!(
        "\n[bench] accept             →  {} CU  (limit {})",
        metadata.compute_units_consumed, MAX_CU
    );
    assert!(
        metadata.compute_units_consumed <= MAX_CU,
        "accept used {} CU, exceeds limit {}",
        metadata.compute_units_consumed,
        MAX_CU
    );
}

#[test]
fn bench_finish() {
    let mut svm = setup_svm();

    let sender = Keypair::new();
    let receiver = Keypair::new();
    let nonce = [103u8; 8];
    fund(&mut svm, &sender.pubkey());
    fund(&mut svm, &receiver.pubkey());

    let v = make_scalar(10);
    let b = make_scalar(20);
    let c = make_scalar(30);
    let r = v - b * c;
    let (vx, vy) = point_to_xy(&ProjectivePoint::mul_by_generator(&v));
    let (bx, by) = point_to_xy(&ProjectivePoint::mul_by_generator(&b));
    let c_bytes = scalar_to_bytes(&c);
    let r_bytes = scalar_to_bytes(&r);

    let (delivery_key, _) = delivery_pda(&sender.pubkey(), &nonce);
    let (vault_key, _) = vault_pda(&delivery_key);

    let create_ix = create_delivery_ix(
        &sender.pubkey(),
        &delivery_key,
        &vault_key,
        vec![receiver.pubkey()],
        vx,
        vy,
        vec![0u8; 32],
        vec![],
        3600,
        7200,
        nonce,
    );
    send_tx(&mut svm, &[create_ix], &sender, &[&sender]);

    let accept = accept_ix(
        &receiver.pubkey(),
        &delivery_key,
        vec![0xAA; 32],
        vec![0xBB; 32],
        bx,
        by,
        c_bytes,
    );
    send_tx(&mut svm, &[accept], &receiver, &[&receiver]);

    let finish = finish_ix(
        &sender.pubkey(),
        &delivery_key,
        &vault_key,
        receiver.pubkey(),
        r_bytes,
    );
    let metadata = send_tx(&mut svm, &[finish], &sender, &[&sender]);
    println!(
        "\n[bench] finish (EC verify) →  {} CU  (limit {})",
        metadata.compute_units_consumed, MAX_CU
    );
    assert!(
        metadata.compute_units_consumed <= MAX_CU,
        "finish used {} CU, exceeds limit {}",
        metadata.compute_units_consumed,
        MAX_CU
    );
}

#[test]
fn bench_cancel() {
    let mut svm = setup_svm();

    let sender = Keypair::new();
    let receiver = Keypair::new();
    let nonce = [104u8; 8];
    fund(&mut svm, &sender.pubkey());
    fund(&mut svm, &receiver.pubkey());

    let v = make_scalar(10);
    let b = make_scalar(20);
    let c = make_scalar(30);
    let (vx, vy) = point_to_xy(&ProjectivePoint::mul_by_generator(&v));
    let (bx, by) = point_to_xy(&ProjectivePoint::mul_by_generator(&b));
    let c_bytes = scalar_to_bytes(&c);

    let (delivery_key, _) = delivery_pda(&sender.pubkey(), &nonce);
    let (vault_key, _) = vault_pda(&delivery_key);

    let create_ix = create_delivery_ix(
        &sender.pubkey(),
        &delivery_key,
        &vault_key,
        vec![receiver.pubkey()],
        vx,
        vy,
        vec![],
        vec![],
        3600,
        7200,
        nonce,
    );
    send_tx(&mut svm, &[create_ix], &sender, &[&sender]);

    let accept = accept_ix(
        &receiver.pubkey(),
        &delivery_key,
        vec![],
        vec![],
        bx,
        by,
        c_bytes,
    );
    send_tx(&mut svm, &[accept], &receiver, &[&receiver]);

    let mut clock: Clock = svm.get_sysvar();
    clock.unix_timestamp += 8000;
    svm.set_sysvar(&clock);

    let cancel = cancel_ix(&receiver.pubkey(), &delivery_key);
    let metadata = send_tx(&mut svm, &[cancel], &receiver, &[&receiver]);
    println!(
        "\n[bench] cancel             →  {} CU  (limit {})",
        metadata.compute_units_consumed, MAX_CU
    );
    assert!(
        metadata.compute_units_consumed <= MAX_CU,
        "cancel used {} CU, exceeds limit {}",
        metadata.compute_units_consumed,
        MAX_CU
    );
}

#[test]
fn bench_full_delivery_flow() {
    let mut svm = setup_svm();

    let sender = Keypair::new();
    let receiver = Keypair::new();
    let nonce = [105u8; 8];
    fund(&mut svm, &sender.pubkey());
    fund(&mut svm, &receiver.pubkey());

    let v = make_scalar(10);
    let b = make_scalar(20);
    let c = make_scalar(30);
    let r = v - b * c;
    let (vx, vy) = point_to_xy(&ProjectivePoint::mul_by_generator(&v));
    let (bx, by) = point_to_xy(&ProjectivePoint::mul_by_generator(&b));
    let c_bytes = scalar_to_bytes(&c);
    let r_bytes = scalar_to_bytes(&r);

    let (delivery_key, _) = delivery_pda(&sender.pubkey(), &nonce);
    let (vault_key, _) = vault_pda(&delivery_key);

    // Step 1: create_delivery
    let create_ix = create_delivery_ix(
        &sender.pubkey(),
        &delivery_key,
        &vault_key,
        vec![receiver.pubkey()],
        vx,
        vy,
        vec![0u8; 32],
        vec![1u8; 64],
        3600,
        7200,
        nonce,
    );
    let r1 = send_tx(&mut svm, &[create_ix], &sender, &[&sender]);
    let cu_create = r1.compute_units_consumed;

    // Step 2: accept
    let accept = accept_ix(
        &receiver.pubkey(),
        &delivery_key,
        vec![0xAA; 32],
        vec![0xBB; 32],
        bx,
        by,
        c_bytes,
    );
    let r2 = send_tx(&mut svm, &[accept], &receiver, &[&receiver]);
    let cu_accept = r2.compute_units_consumed;

    // Step 3: finish
    let finish = finish_ix(
        &sender.pubkey(),
        &delivery_key,
        &vault_key,
        receiver.pubkey(),
        r_bytes,
    );
    let r3 = send_tx(&mut svm, &[finish], &sender, &[&sender]);
    let cu_finish = r3.compute_units_consumed;

    // Summary
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
