

from vuln_agent.solana_security import scan_solana_programs

# A deliberately vulnerable Anchor-style program exercising each heuristic. It is sample source
# for the static scanner, never deployed and never executed.
VULNERABLE_SALE = """
use anchor_lang::prelude::*;

#[program]
pub mod sale {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let state = &mut ctx.accounts.state;
        state.total_raised -= amount;                 // unchecked arithmetic
        token::transfer(ctx.accounts.transfer_ctx(), amount)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub state: Account<'info, SaleState>,
    #[account(mut)]
    pub authority: AccountInfo<'info>,               // authority without signer/constraint
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,              // unchecked, no /// CHECK
    #[account(seeds = [b"vault", state.key().as_ref()])]
    pub vault_pda: AccountInfo<'info>,               // seeds without bump
}
"""

SAFE_SALE = """
use anchor_lang::prelude::*;

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let state = &mut ctx.accounts.state;
    state.total_raised = state.total_raised.checked_sub(amount).ok_or(SaleError::Overflow)?;
    Ok(())
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = authority)]
    pub state: Account<'info, SaleState>,
    pub authority: Signer<'info>,
    /// CHECK: validated by seeds + bump below
    #[account(seeds = [b"vault", state.key().as_ref()], bump = state.vault_bump)]
    pub vault: AccountInfo<'info>,
}
"""


def write(tmp_path, name, content):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def rules(findings):
    return {f["rule_id"] for f in findings}


def test_flags_each_vulnerability_class(tmp_path):
    write(tmp_path, "programs/sale/src/lib.rs", VULNERABLE_SALE)
    found = rules(scan_solana_programs(tmp_path))
    for rule in (
        "vulnagent.solana.unchecked-arithmetic",
        "vulnagent.solana.authority-without-check",
        "vulnagent.solana.unchecked-account",
        "vulnagent.solana.pda-without-bump",
        "vulnagent.solana.spl-token-op",
    ):
        assert rule in found, rule


def test_findings_are_triaged_for_manual_review(tmp_path):
    write(tmp_path, "lib.rs", VULNERABLE_SALE)
    findings = scan_solana_programs(tmp_path)
    assert findings
    for f in findings:
        assert f["triage_status"] == "needs_manual_review"
        assert f["source"] == "heurística Solana/Anchor"
        assert f["rule_id"].startswith("vulnagent.solana.")


def test_safe_program_is_quiet(tmp_path):
    write(tmp_path, "lib.rs", SAFE_SALE)
    found = rules(scan_solana_programs(tmp_path))
    assert "vulnagent.solana.authority-without-check" not in found
    assert "vulnagent.solana.unchecked-account" not in found
    assert "vulnagent.solana.pda-without-bump" not in found
    assert "vulnagent.solana.unchecked-arithmetic" not in found


def test_init_if_needed_and_invoke_signed(tmp_path):
    write(tmp_path, "vesting.rs",
          "pub fn claim() { let x = invoke_signed(&ix, &accounts, &[seeds])?; }\n"
          "#[account(init_if_needed, payer = user, space = 8)]\n")
    found = rules(scan_solana_programs(tmp_path))
    assert "vulnagent.solana.init-if-needed" in found
    assert "vulnagent.solana.invoke-signed" in found


def test_native_handler_without_signer_check(tmp_path):
    write(tmp_path, "processor.rs",
          "let acc = next_account_info(iter)?;\nlet auth = next_account_info(iter)?;\n"
          "**auth.try_borrow_mut_lamports()? -= amount;\n")
    found = rules(scan_solana_programs(tmp_path))
    assert "vulnagent.solana.native-missing-signer" in found
    assert "vulnagent.solana.manual-lamports" in found


def test_native_handler_with_signer_check_is_quiet(tmp_path):
    write(tmp_path, "processor.rs",
          "let auth = next_account_info(iter)?;\nif !auth.is_signer { return Err(ProgramError::MissingRequiredSignature.into()); }\n")
    assert "vulnagent.solana.native-missing-signer" not in rules(scan_solana_programs(tmp_path))


def test_cargo_overflow_checks(tmp_path):
    write(tmp_path, "Cargo.toml",
          '[package]\nname = "sale"\n\n[dependencies]\nanchor-lang = "0.30"\n\n[profile.release]\nlto = true\n')
    assert "vulnagent.solana.cargo-overflow-checks" in rules(scan_solana_programs(tmp_path))
    write(tmp_path, "ok/Cargo.toml",
          '[dependencies]\nanchor-lang = "0.30"\n\n[profile.release]\noverflow-checks = true\n')
    assert "vulnagent.solana.cargo-overflow-checks" not in rules(scan_solana_programs(tmp_path / "ok"))
    # A non-program crate (e.g. a build tool) is not flagged even without overflow-checks.
    write(tmp_path, "tool/Cargo.toml", '[package]\nname = "tool"\n\n[dependencies]\nclap = "4"\n')
    assert "vulnagent.solana.cargo-overflow-checks" not in rules(scan_solana_programs(tmp_path / "tool"))


def test_target_build_dir_is_skipped(tmp_path):
    write(tmp_path, "target/debug/generated.rs", VULNERABLE_SALE)
    assert scan_solana_programs(tmp_path) == []


def test_commented_arithmetic_is_ignored(tmp_path):
    write(tmp_path, "note.rs", "// state.balance -= amount is intentional here\n")
    assert "vulnagent.solana.unchecked-arithmetic" not in rules(scan_solana_programs(tmp_path))
