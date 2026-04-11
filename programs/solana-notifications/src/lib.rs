use anchor_lang::prelude::*;

declare_id!("796WZ74WaKoGxYCpxeN2Ekb38SH7ptQuM9HSZeGHyY4z");

#[program]
pub mod solana_notifications {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        msg!("Greetings from: {:?}", ctx.program_id);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize {}
