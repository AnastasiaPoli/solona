#![cfg(feature = "full")]

use crate::{
    process_instruction::BpfComputeBudget,
    transaction::{Transaction, TransactionError},
};
use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use solana_sdk::{
    borsh::try_from_slice_unchecked,
    instruction::{Instruction, InstructionError},
};

crate::declare_id!("ComputeBudget111111111111111111111111111111");

const MAX_UNITS: u32 = 1_000_000;

/// Compute Budget Instructions
#[derive(
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Debug,
    Clone,
    PartialEq,
    AbiExample,
    AbiEnumVisitor,
)]
pub enum ComputeBudgetInstruction {
    /// Request a specific maximum number of compute units the transaction is
    /// allowed to consume.
    RequestUnits(u32),
}
<<<<<<< HEAD
=======
impl ComputeBudgetInstruction {
    /// Create a `ComputeBudgetInstruction::RequestUnits` `Instruction`
    pub fn request_units(units: u32) -> Instruction {
        Instruction::new_with_borsh(id(), &ComputeBudgetInstruction::RequestUnits(units), vec![])
    }
}
>>>>>>> c231cfe23 (Reduce budget request instruction length (#20636))

/// Create a `ComputeBudgetInstruction::RequestUnits` `Instruction`
pub fn request_units(units: u64) -> Instruction {
    Instruction::new_with_borsh(id(), &ComputeBudgetInstruction::RequestUnits(units), vec![])
}
<<<<<<< HEAD

pub fn process_request(
    compute_budget: &mut BpfComputeBudget,
    tx: &Transaction,
) -> Result<(), TransactionError> {
    let error = TransactionError::InstructionError(0, InstructionError::InvalidInstructionData);
    // Compute budget instruction must be in 1st or 2nd instruction (avoid nonce marker)
    for instruction in tx.message().instructions.iter().take(2) {
        if check_id(instruction.program_id(&tx.message().account_keys)) {
            let ComputeBudgetInstruction::RequestUnits(units) =
                try_from_slice_unchecked::<ComputeBudgetInstruction>(&instruction.data)
                    .map_err(|_| error.clone())?;
            if units > MAX_UNITS {
                return Err(error);
=======
impl Default for ComputeBudget {
    fn default() -> Self {
        Self::new()
    }
}
impl ComputeBudget {
    pub fn new() -> Self {
        ComputeBudget {
            max_units: 200_000,
            log_64_units: 100,
            create_program_address_units: 1500,
            invoke_units: 1000,
            max_invoke_depth: 4,
            sha256_base_cost: 85,
            sha256_byte_cost: 1,
            max_call_depth: 64,
            stack_frame_size: 4_096,
            log_pubkey_units: 100,
            max_cpi_instruction_size: 1280, // IPv6 Min MTU size
            cpi_bytes_per_unit: 250,        // ~50MB at 200,000 units
            sysvar_base_cost: 100,
            secp256k1_recover_cost: 25_000,
            syscall_base_cost: 100,
            heap_size: None,
        }
    }
    pub fn process_transaction(
        &mut self,
        tx: &SanitizedTransaction,
    ) -> Result<(), TransactionError> {
        let error = TransactionError::InstructionError(0, InstructionError::InvalidInstructionData);
        // Compute budget instruction must be in 1st or 2nd instruction (avoid nonce marker)
        for (program_id, instruction) in tx.message().program_instructions_iter().take(2) {
            if check_id(program_id) {
                let ComputeBudgetInstruction::RequestUnits(units) =
                    try_from_slice_unchecked::<ComputeBudgetInstruction>(&instruction.data)
                        .map_err(|_| error.clone())?;
                if units > MAX_UNITS {
                    return Err(error);
                }
                self.max_units = units as u64;
>>>>>>> c231cfe23 (Reduce budget request instruction length (#20636))
            }
            compute_budget.max_units = units;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        compute_budget, hash::Hash, message::Message, pubkey::Pubkey, signature::Keypair,
        signer::Signer,
    };

    #[test]
    fn test_process_request() {
        let payer_keypair = Keypair::new();
        let mut compute_budget = BpfComputeBudget::default();

        let tx = Transaction::new(
            &[&payer_keypair],
            Message::new(&[], Some(&payer_keypair.pubkey())),
            Hash::default(),
        );
        process_request(&mut compute_budget, &tx).unwrap();
        assert_eq!(compute_budget, BpfComputeBudget::default());

        let tx = Transaction::new(
            &[&payer_keypair],
            Message::new(
                &[
                    compute_budget::request_units(1),
                    Instruction::new_with_bincode(Pubkey::new_unique(), &0, vec![]),
                ],
                Some(&payer_keypair.pubkey()),
            ),
            Hash::default(),
        );
        process_request(&mut compute_budget, &tx).unwrap();
        assert_eq!(
            compute_budget,
            BpfComputeBudget {
                max_units: 1,
                ..BpfComputeBudget::default()
            }
        );

        let tx = Transaction::new(
            &[&payer_keypair],
            Message::new(
                &[
                    compute_budget::request_units(MAX_UNITS + 1),
                    Instruction::new_with_bincode(Pubkey::new_unique(), &0, vec![]),
                ],
                Some(&payer_keypair.pubkey()),
            ),
            Hash::default(),
        );
        let result = process_request(&mut compute_budget, &tx);
        assert_eq!(
            result,
            Err(TransactionError::InstructionError(
                0,
                InstructionError::InvalidInstructionData
            ))
        );

        let tx = Transaction::new(
            &[&payer_keypair],
            Message::new(
                &[
                    Instruction::new_with_bincode(Pubkey::new_unique(), &0, vec![]),
                    compute_budget::request_units(MAX_UNITS),
                ],
                Some(&payer_keypair.pubkey()),
            ),
            Hash::default(),
        );
        process_request(&mut compute_budget, &tx).unwrap();
        assert_eq!(
            compute_budget,
<<<<<<< HEAD
            BpfComputeBudget {
                max_units: MAX_UNITS,
                ..BpfComputeBudget::default()
=======
            ComputeBudget {
                max_units: MAX_UNITS as u64,
                ..ComputeBudget::default()
>>>>>>> c231cfe23 (Reduce budget request instruction length (#20636))
            }
        );
    }
}
