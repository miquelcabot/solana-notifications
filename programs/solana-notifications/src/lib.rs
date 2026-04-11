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
        require!(term1 > 0 && term1 < term2, SolanaNotificationsError::InvalidTerms);
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
            receivers: delivery.receiver_states.iter().map(|rs| rs.receiver).collect(),
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

        require!(
            clock.unix_timestamp < delivery.start + delivery.term1,
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

        delivery.accepted_receivers += 1;

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
    /// The sender provides `r`. If at least one receiver has accepted, the program
    /// verifies on-chain that `V == G·r + B·c` (secp256k1) using the first accepted
    /// receiver's stored (B, c). On success:
    /// - `Accepted` → `Finished` (r is stored in each finished receiver's state),
    /// - `Created`  → `Rejected`.
    ///
    /// The sender's deposit is returned from the vault.
    pub fn finish(ctx: Context<FinishDelivery>, r: [u8; 32]) -> Result<()> {
        let clock = Clock::get()?;

        // --- Immutable validation scope ---
        {
            let delivery = &ctx.accounts.delivery;

            let all_accepted =
                delivery.accepted_receivers == delivery.receiver_states.len() as u32;
            let time_passed = clock.unix_timestamp >= delivery.start + delivery.term1;
            require!(
                all_accepted || time_passed,
                SolanaNotificationsError::FinishConditionsNotMet
            );
            require!(!delivery.finished, SolanaNotificationsError::AlreadyFinished);

            // If any receiver accepted, verify the cryptographic proof for that receiver.
            if let Some(accepted) = delivery
                .receiver_states
                .iter()
                .find(|rs| rs.state == State::Accepted)
            {
                verify_cryptographic_proof(
                    delivery.vx,
                    delivery.vy,
                    accepted.bx,
                    accepted.by,
                    accepted.c,
                    r,
                )?;
            }
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

        require!(
            clock.unix_timestamp >= delivery.start + delivery.term2,
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

/// Verifies `V == G·r + B·c` on the secp256k1 curve.
///
/// - `V = (vx, vy)`: sender's commitment point.
/// - `B = (bx, by)`: receiver's EC point submitted during acceptance.
/// - `c`: challenge scalar submitted by the receiver.
/// - `r`: response scalar revealed by the sender at finish time.
///
/// The equation holds when `r = v - b·c` (i.e., `V = G·v`, `B = G·b`),
/// which proves the sender knows the discrete log `v` of `V`.
fn verify_cryptographic_proof(
    vx: [u8; 32],
    vy: [u8; 32],
    bx: [u8; 32],
    by: [u8; 32],
    c: [u8; 32],
    r: [u8; 32],
) -> Result<()> {
    use k256::{elliptic_curve::ops::MulByGenerator, ProjectivePoint};

    let r_scalar = bytes_to_scalar(&r)?;
    let c_scalar = bytes_to_scalar(&c)?;

    let b_point = bytes_to_projective_point(&bx, &by)?;
    let v_point = bytes_to_projective_point(&vx, &vy)?;

    // Compute G·r + B·c
    let computed = ProjectivePoint::mul_by_generator(&r_scalar) + b_point * c_scalar;

    require!(
        computed == v_point,
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

fn bytes_to_projective_point(x: &[u8; 32], y: &[u8; 32]) -> Result<k256::ProjectivePoint> {
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    // Uncompressed SEC1 encoding: 0x04 || x || y
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(x);
    sec1[33..65].copy_from_slice(y);

    let encoded = k256::EncodedPoint::from_bytes(&sec1)
        .map_err(|_| error!(SolanaNotificationsError::InvalidPoint))?;

    let affine = k256::AffinePoint::from_encoded_point(&encoded)
        .into_option()
        .ok_or(error!(SolanaNotificationsError::InvalidPoint))?;

    Ok(k256::ProjectivePoint::from(affine))
}

// ===================== Account Structures =====================

/// State of the delivery process for a single receiver.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq)]
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
        + 1;                                        // state  →  937 bytes
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
        + 8;                                                    // nonce  →  ≈9845 bytes
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
    #[msg("Finish conditions not met: all receivers must have accepted or term1 must have elapsed")]
    FinishConditionsNotMet,
    #[msg("Delivery is already finished")]
    AlreadyFinished,
    #[msg("Cryptographic verification failed: V != G·r + B·c")]
    VAndGxRiPlusBiXCiNotEqual,
    #[msg("Cancel window not reached: current time < start + term2")]
    CancelWindowNotReached,
    #[msg("Unauthorized: caller is not the delivery sender")]
    Unauthorized,
    #[msg("Invalid scalar: bytes could not be decoded as a secp256k1 scalar")]
    InvalidScalar,
    #[msg("Invalid point: bytes could not be decoded as a secp256k1 affine point")]
    InvalidPoint,
}
