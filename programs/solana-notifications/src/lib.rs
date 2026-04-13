use anchor_lang::prelude::*;

declare_id!("796WZ74WaKoGxYCpxeN2Ekb38SH7ptQuM9HSZeGHyY4z");

// ===================== Constants =====================

pub const MAX_RECEIVERS: usize = 10;
pub const MAX_Z1_SIZE: usize = 256;
pub const MAX_Z2_SIZE: usize = 512;
pub const MAX_ENCRYPTED_HASH_SIZE: usize = 64;
pub const MAX_A_SIZE: usize = 256;
/// Deposit locked by the sender when creating a delivery (0.1 SOL).
pub const DELIVERY_DEPOSIT: u64 = 100_000_000;

// ===================== Program =====================

#[program]
pub mod solana_notifications {
    use super::*;

    /// Creates a new certified e-delivery.
    ///
    /// The sender locks `DELIVERY_DEPOSIT` lamports in a vault PDA and records:
    /// - the list of receivers,
    /// - the EC commitment point V = (vx, vy),
    /// - the encrypted-message hash and auxiliary data `a`,
    /// - two time windows: term1 (acceptance deadline) and term2 (cancellation open).
    ///
    /// All receivers are initialised in the `Created` state.
    pub fn create_delivery(
        ctx: Context<CreateDelivery>,
        receivers: Vec<Pubkey>,
        vx: [u8; 32],
        vy: [u8; 32],
        encrypted_message_hash: Vec<u8>,
        a: Vec<u8>,
        term1: i64,
        term2: i64,
        nonce: [u8; 8],
    ) -> Result<()> {
        require!(
            !receivers.is_empty() && receivers.len() <= MAX_RECEIVERS,
            SolanaNotificationsError::InvalidReceiversCount
        );
        for i in 0..receivers.len() {
            for j in (i + 1)..receivers.len() {
                require!(
                    receivers[i] != receivers[j],
                    SolanaNotificationsError::DuplicateReceiver
                );
            }
        }
        require!(
            term1 > 0 && term1 < term2,
            SolanaNotificationsError::InvalidTerms
        );
        require!(
            encrypted_message_hash.len() <= MAX_ENCRYPTED_HASH_SIZE,
            SolanaNotificationsError::InvalidEncryptedHash
        );
        require!(a.len() <= MAX_A_SIZE, SolanaNotificationsError::InvalidA);

        let clock = Clock::get()?;
        let delivery = &mut ctx.accounts.delivery;

        delivery.sender = ctx.accounts.sender.key();
        delivery.receiver_states = receivers
            .iter()
            .map(|&r| ReceiverState {
                receiver: r,
                z1: vec![],
                z2: vec![],
                bx: [0u8; 32],
                by: [0u8; 32],
                c: [0u8; 32],
                r: [0u8; 32],
                state: State::Created,
            })
            .collect();
        delivery.vx = vx;
        delivery.vy = vy;
        delivery.encrypted_message_hash = encrypted_message_hash;
        delivery.a = a;
        delivery.start = clock.unix_timestamp;
        delivery.term1 = term1;
        delivery.term2 = term2;
        delivery.accepted_receivers = 0;
        delivery.finished = false;
        delivery.bump = ctx.bumps.delivery;
        delivery.vault_bump = ctx.bumps.vault;
        delivery.nonce = nonce;

        // Lock deposit in vault PDA
        anchor_lang::system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.sender.to_account_info(),
                    to: ctx.accounts.vault.to_account_info(),
                },
            ),
            DELIVERY_DEPOSIT,
        )?;

        emit!(DeliveryCreated {
            delivery: delivery.key(),
            sender: delivery.sender,
            receivers: delivery
                .receiver_states
                .iter()
                .map(|rs| rs.receiver)
                .collect(),
            start: delivery.start,
            term1: delivery.term1,
            term2: delivery.term2,
        });

        Ok(())
    }

    /// Called by a receiver to accept the delivery during [start, start+term1).
    ///
    /// The receiver submits their cryptographic transcript:
    /// - `z1`, `z2`: zero-knowledge commitment blobs (stored for evidence, not verified on-chain),
    /// - `B = (bx, by)`: the receiver's EC point,
    /// - `c`: the challenge value.
    ///
    /// The receiver transitions from `Created` to `Accepted`.
    pub fn accept(
        ctx: Context<AcceptDelivery>,
        z1: Vec<u8>,
        z2: Vec<u8>,
        bx: [u8; 32],
        by: [u8; 32],
        c: [u8; 32],
    ) -> Result<()> {
        require!(z1.len() <= MAX_Z1_SIZE, SolanaNotificationsError::InvalidZ1);
        require!(z2.len() <= MAX_Z2_SIZE, SolanaNotificationsError::InvalidZ2);

        let delivery = &mut ctx.accounts.delivery;
        let receiver_key = ctx.accounts.receiver.key();
        let clock = Clock::get()?;

        let accept_deadline = delivery
            .start
            .checked_add(delivery.term1)
            .ok_or(SolanaNotificationsError::InvalidTerms)?;
        require!(
            clock.unix_timestamp < accept_deadline,
            SolanaNotificationsError::AcceptWindowExpired
        );

        let receiver_state = delivery
            .receiver_states
            .iter_mut()
            .find(|rs| rs.receiver == receiver_key)
            .ok_or(SolanaNotificationsError::ReceiverNotFound)?;

        require!(
            receiver_state.state == State::Created,
            SolanaNotificationsError::InvalidState
        );

        receiver_state.z1 = z1;
        receiver_state.z2 = z2;
        receiver_state.bx = bx;
        receiver_state.by = by;
        receiver_state.c = c;
        receiver_state.state = State::Accepted;

        delivery.accepted_receivers = delivery
            .accepted_receivers
            .checked_add(1)
            .ok_or(SolanaNotificationsError::InvalidReceiversCount)?;

        emit!(ReceiverAccepted {
            delivery: delivery.key(),
            receiver: receiver_key,
        });

        Ok(())
    }

    /// Called by the sender to complete the delivery.
    ///
    /// Pre-conditions (either):
    /// - all receivers have accepted, OR
    /// - the acceptance window (term1) has elapsed.
    ///
    /// The sender specifies which `receiver`'s (B, c) to use for proof verification
    /// and provides the response scalar `r`. The program verifies on-chain that
    /// `V == G·r + B·c` (secp256k1). On success:
    /// - `Accepted` → `Finished` (r is stored in each finished receiver's state),
    /// - `Created`  → `Rejected`.
    ///
    /// The sender's deposit is returned from the vault.
    pub fn finish(ctx: Context<FinishDelivery>, receiver: Pubkey, r: [u8; 32]) -> Result<()> {
        let clock = Clock::get()?;

        // --- Immutable validation scope ---
        {
            let delivery = &ctx.accounts.delivery;

            let all_accepted = delivery.accepted_receivers == delivery.receiver_states.len() as u32;
            let finish_deadline = delivery
                .start
                .checked_add(delivery.term1)
                .ok_or(SolanaNotificationsError::InvalidTerms)?;
            let time_passed = clock.unix_timestamp >= finish_deadline;
            require!(
                all_accepted || time_passed,
                SolanaNotificationsError::FinishConditionsNotMet
            );
            require!(
                !delivery.finished,
                SolanaNotificationsError::AlreadyFinished
            );

            // Verify the cryptographic proof against the specified receiver.
            let receiver_state = delivery
                .receiver_states
                .iter()
                .find(|rs| rs.receiver == receiver && rs.state == State::Accepted)
                .ok_or(SolanaNotificationsError::ReceiverNotAccepted)?;

            verify_cryptographic_proof(
                delivery.vx,
                delivery.vy,
                receiver_state.bx,
                receiver_state.by,
                receiver_state.c,
                r,
            )?;
        }

        // Save values needed after the mutable borrow
        let delivery_key = ctx.accounts.delivery.key();
        let vault_bump = ctx.accounts.delivery.vault_bump;
        let sender_key = ctx.accounts.delivery.sender;
        let vault_balance = ctx.accounts.vault.lamports();

        // --- Mutable state update scope ---
        {
            let delivery = &mut ctx.accounts.delivery;
            for rs in delivery.receiver_states.iter_mut() {
                rs.state = match rs.state {
                    State::Accepted => {
                        rs.r = r;
                        State::Finished
                    }
                    State::Created => State::Rejected,
                    ref s => s.clone(),
                };
            }
            delivery.finished = true;
        }

        // Return deposit to sender via signed CPI
        anchor_lang::system_program::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.vault.to_account_info(),
                    to: ctx.accounts.sender.to_account_info(),
                },
                &[&[b"vault", delivery_key.as_ref(), &[vault_bump]]],
            ),
            vault_balance,
        )?;

        emit!(DeliveryFinished {
            delivery: delivery_key,
            sender: sender_key,
        });

        Ok(())
    }

    /// Called by a receiver to cancel their participation after term2 has elapsed.
    ///
    /// Only valid for receivers in the `Accepted` state.
    /// Transitions the receiver from `Accepted` to `Cancelled`.
    pub fn cancel(ctx: Context<CancelDelivery>) -> Result<()> {
        let delivery = &mut ctx.accounts.delivery;
        let receiver_key = ctx.accounts.receiver.key();
        let clock = Clock::get()?;

        let cancel_deadline = delivery
            .start
            .checked_add(delivery.term2)
            .ok_or(SolanaNotificationsError::InvalidTerms)?;
        require!(
            clock.unix_timestamp >= cancel_deadline,
            SolanaNotificationsError::CancelWindowNotReached
        );

        let receiver_state = delivery
            .receiver_states
            .iter_mut()
            .find(|rs| rs.receiver == receiver_key)
            .ok_or(SolanaNotificationsError::ReceiverNotFound)?;

        require!(
            receiver_state.state == State::Accepted,
            SolanaNotificationsError::InvalidState
        );

        receiver_state.state = State::Cancelled;

        emit!(ReceiverCancelled {
            delivery: delivery.key(),
            receiver: receiver_key,
        });

        Ok(())
    }
}

// ===================== Cryptographic Verification =====================

/// Verifies `V == G·r + B·c` on the secp256k1 curve using Solana's native
/// `secp256k1_recover` syscall instead of software EC arithmetic.
///
/// **Why secp256k1_recover instead of k256 EC arithmetic?**
/// Software EC point multiplication in BPF costs >1.4 M compute units (the
/// per-transaction maximum).  The `secp256k1_recover` syscall runs native C
/// code and costs only ~25 000 CU.
///
/// **Reformulation** — secp256k1_recover computes:
///   `Q = r_sig⁻¹ · (s · R − hash · G)`
/// where R is the curve point whose x-coordinate equals r_sig.
///
/// Setting `R = B` (recovery_id selects the matching y), `r_sig = B.x`,
/// `hash = −r·B.x mod n`, `s = c·B.x mod n`:
///   `Q = B.x⁻¹ · (c·B.x · B − (−r·B.x) · G)`
///      = `c · B + r · G`
///      = `G·r + B·c`
///
/// So we check that `secp256k1_recover(hash, rec_id, B.x ‖ s) == V`.
/// All intermediate values are **scalar field multiplications** (cheap integer
/// arithmetic in Z_n), not EC point operations.
fn verify_cryptographic_proof(
    vx: [u8; 32],
    vy: [u8; 32],
    bx: [u8; 32],
    by: [u8; 32],
    c: [u8; 32],
    r: [u8; 32],
) -> Result<()> {
    use solana_secp256k1_recover::secp256k1_recover;

    let resp = bytes_to_scalar(&r)?;
    let c_scalar = bytes_to_scalar(&c)?;
    let bx_scalar = bytes_to_scalar(&bx)?;

    // hash = −r · B.x mod n  (scalar multiplication, no EC operations)
    let hash_scalar = -(resp * bx_scalar);
    let hash_bytes: [u8; 32] = hash_scalar.to_bytes().into();

    // s = c · B.x mod n
    let s_bytes: [u8; 32] = (c_scalar * bx_scalar).to_bytes().into();

    // signature = r_sig (32 B) ‖ s_sig (32 B)
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&bx); // r_sig = B.x
    signature[32..].copy_from_slice(&s_bytes);

    // recovery_id: 0 = even y, 1 = odd y (least-significant bit of B.y)
    let recovery_id = by[31] & 1;

    let recovered = secp256k1_recover(&hash_bytes, recovery_id, &signature)
        .map_err(|_| error!(SolanaNotificationsError::VAndGxRiPlusBiXCiNotEqual))?;

    // secp256k1_recover returns 64 bytes: x (32) ‖ y (32), no 0x04 prefix
    let rec = recovered.to_bytes();
    require!(
        rec[..32] == vx && rec[32..] == vy,
        SolanaNotificationsError::VAndGxRiPlusBiXCiNotEqual
    );

    Ok(())
}

fn bytes_to_scalar(bytes: &[u8; 32]) -> Result<k256::Scalar> {
    use k256::elliptic_curve::ScalarPrimitive;
    let prim = ScalarPrimitive::from_slice(bytes)
        .map_err(|_| error!(SolanaNotificationsError::InvalidScalar))?;
    Ok(k256::Scalar::from(prim))
}

// ===================== Account Structures =====================

/// State of the delivery process for a single receiver.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Debug)]
pub enum State {
    NotExists,
    Created,
    Cancelled,
    Accepted,
    Finished,
    Rejected,
}

/// Per-receiver cryptographic transcript, embedded inline in [`Delivery`].
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ReceiverState {
    pub receiver: Pubkey, // 32
    pub z1: Vec<u8>,      // 4 + ≤256
    pub z2: Vec<u8>,      // 4 + ≤512
    pub bx: [u8; 32],     // 32  — receiver's EC point X
    pub by: [u8; 32],     // 32  — receiver's EC point Y
    pub c: [u8; 32],      // 32  — challenge scalar
    pub r: [u8; 32],      // 32  — response scalar (filled at finish)
    pub state: State,     // 1
}

impl ReceiverState {
    /// Maximum serialised size in bytes.
    pub const MAX_SIZE: usize = 32                  // receiver
        + (4 + MAX_Z1_SIZE)                         // z1
        + (4 + MAX_Z2_SIZE)                         // z2
        + 32 + 32 + 32 + 32                         // bx, by, c, r
        + 1; // state  →  937 bytes
}

/// Main delivery account (PDA).
///
/// Seeds: `["delivery", sender, nonce]`.
#[account]
pub struct Delivery {
    pub sender: Pubkey,                      // 32
    pub receiver_states: Vec<ReceiverState>, // 4 + MAX_RECEIVERS × ReceiverState::MAX_SIZE
    pub vx: [u8; 32],                        // 32 — sender's commitment X
    pub vy: [u8; 32],                        // 32 — sender's commitment Y
    pub encrypted_message_hash: Vec<u8>,     // 4 + ≤64
    pub a: Vec<u8>,                          // 4 + ≤256
    pub start: i64,                          // 8
    pub term1: i64,                          // 8 — seconds until acceptance closes
    pub term2: i64,                          // 8 — seconds until cancellation opens
    pub accepted_receivers: u32,             // 4
    pub finished: bool,                      // 1
    pub bump: u8,                            // 1
    pub vault_bump: u8,                      // 1
    pub nonce: [u8; 8],                      // 8
}

impl Delivery {
    /// Maximum serialised size in bytes (includes Anchor 8-byte discriminator).
    pub const MAX_SIZE: usize = 8                               // discriminator
        + 32                                                    // sender
        + (4 + MAX_RECEIVERS * ReceiverState::MAX_SIZE)         // receiver_states  (4+9370)
        + 32 + 32                                               // vx, vy
        + (4 + MAX_ENCRYPTED_HASH_SIZE)                         // encrypted_message_hash
        + (4 + MAX_A_SIZE)                                      // a
        + 8 + 8 + 8                                             // start, term1, term2
        + 4                                                     // accepted_receivers
        + 1 + 1 + 1                                             // finished, bump, vault_bump
        + 8; // nonce  →  ≈9845 bytes
}

// ===================== Instruction Contexts =====================

#[derive(Accounts)]
#[instruction(
    receivers: Vec<Pubkey>,
    vx: [u8; 32], vy: [u8; 32],
    encrypted_message_hash: Vec<u8>,
    a: Vec<u8>,
    term1: i64, term2: i64,
    nonce: [u8; 8]
)]
pub struct CreateDelivery<'info> {
    #[account(mut)]
    pub sender: Signer<'info>,

    #[account(
        init,
        payer = sender,
        space = Delivery::MAX_SIZE,
        seeds = [b"delivery", sender.key().as_ref(), nonce.as_ref()],
        bump
    )]
    pub delivery: Account<'info, Delivery>,

    /// CHECK: Vault PDA holding the sender's deposit.
    /// Derived as `["vault", delivery]`; funded via SOL transfer on create.
    #[account(
        mut,
        seeds = [b"vault", delivery.key().as_ref()],
        bump
    )]
    pub vault: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AcceptDelivery<'info> {
    #[account(mut)]
    pub receiver: Signer<'info>,

    #[account(
        mut,
        constraint = delivery.receiver_states.iter().any(|rs| rs.receiver == receiver.key())
            @ SolanaNotificationsError::ReceiverNotFound
    )]
    pub delivery: Account<'info, Delivery>,
}

#[derive(Accounts)]
pub struct FinishDelivery<'info> {
    #[account(mut)]
    pub sender: Signer<'info>,

    #[account(
        mut,
        constraint = delivery.sender == sender.key() @ SolanaNotificationsError::Unauthorized
    )]
    pub delivery: Account<'info, Delivery>,

    /// CHECK: Vault PDA from which the deposit is returned.
    #[account(
        mut,
        seeds = [b"vault", delivery.key().as_ref()],
        bump = delivery.vault_bump
    )]
    pub vault: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CancelDelivery<'info> {
    #[account(mut)]
    pub receiver: Signer<'info>,

    #[account(
        mut,
        constraint = delivery.receiver_states.iter().any(|rs| rs.receiver == receiver.key())
            @ SolanaNotificationsError::ReceiverNotFound
    )]
    pub delivery: Account<'info, Delivery>,
}

// ===================== Events =====================

#[event]
pub struct DeliveryCreated {
    pub delivery: Pubkey,
    pub sender: Pubkey,
    pub receivers: Vec<Pubkey>,
    pub start: i64,
    pub term1: i64,
    pub term2: i64,
}

#[event]
pub struct ReceiverAccepted {
    pub delivery: Pubkey,
    pub receiver: Pubkey,
}

#[event]
pub struct DeliveryFinished {
    pub delivery: Pubkey,
    pub sender: Pubkey,
}

#[event]
pub struct ReceiverCancelled {
    pub delivery: Pubkey,
    pub receiver: Pubkey,
}

// ===================== Errors =====================

#[error_code]
pub enum SolanaNotificationsError {
    #[msg("Number of receivers must be between 1 and MAX_RECEIVERS (10)")]
    InvalidReceiversCount,
    #[msg("Duplicate receiver in the receivers list")]
    DuplicateReceiver,
    #[msg("term1 must be positive and strictly less than term2")]
    InvalidTerms,
    #[msg("encrypted_message_hash exceeds 64 bytes")]
    InvalidEncryptedHash,
    #[msg("Parameter 'a' exceeds 256 bytes")]
    InvalidA,
    #[msg("z1 exceeds 256 bytes")]
    InvalidZ1,
    #[msg("z2 exceeds 512 bytes")]
    InvalidZ2,
    #[msg("Accept window expired: current time >= start + term1")]
    AcceptWindowExpired,
    #[msg("Receiver not found in this delivery")]
    ReceiverNotFound,
    #[msg("Invalid state for this operation")]
    InvalidState,
    #[msg(
        "Finish conditions not met: all receivers must have accepted or term1 must have elapsed"
    )]
    FinishConditionsNotMet,
    #[msg("Delivery is already finished")]
    AlreadyFinished,
    #[msg("Cryptographic verification failed: V != G·r + B·c")]
    VAndGxRiPlusBiXCiNotEqual,
    #[msg("Specified receiver has not accepted this delivery")]
    ReceiverNotAccepted,
    #[msg("Cancel window not reached: current time < start + term2")]
    CancelWindowNotReached,
    #[msg("Unauthorized: caller is not the delivery sender")]
    Unauthorized,
    #[msg("Invalid scalar: bytes could not be decoded as a secp256k1 scalar")]
    InvalidScalar,
    #[msg("Invalid point: bytes could not be decoded as a secp256k1 affine point")]
    InvalidPoint,
}
