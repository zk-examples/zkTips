# zkTips

A privacy-preserving tipping system built with zero-knowledge proofs that allows users to send tips anonymously while maintaining confidentiality of amounts.

## Features

- Anonymous tipping using zero-knowledge proofs
- Encrypted balances using homomorphic encryption
- Deposit and withdrawal functionality
- Allowance and approval system similar to ERC-20
- Merkle tree commitment scheme for privacy

## Technical Overview

The system uses several cryptographic primitives:

- Circom and SnarkJS for zero-knowledge proof generation and verification
- Paillier homomorphic encryption for balance confidentiality
- MiMC hash function for commitments
- Merkle trees for tracking deposits and withdrawals
