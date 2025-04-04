pragma circom 2.1.6;

include "commitmentHasher.circom";
include "merkleTreeChecker.circom";
include "balanceChecker.circom";

template nullifyDepositCommitment(levels) {
    signal input nullifier;
    signal input secret;
    signal input value;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal input encryptedBalance;
	// public key: g, rand r, n
	signal input pubKey[3];

    signal output nullifierHash;
    signal output root;

    component commitmentHasher = CommitmentHasher();
    component merkleTreeChecker = MerkleTreeChecker(levels);
    component balanceChecker = BalanceChecker();

    commitmentHasher.nullifier <== nullifier;
    commitmentHasher.secret <== secret;
    commitmentHasher.value <== value;

    balanceChecker.encryptedBalance <== encryptedBalance;
    balanceChecker.balance <== value;
    balanceChecker.pubKey <== pubKey;

    merkleTreeChecker.leaf <== commitmentHasher.commitment;
    for (var i = 0; i < levels; i++) {
        merkleTreeChecker.pathElements[i] <== pathElements[i];
        merkleTreeChecker.pathIndices[i] <== pathIndices[i];
    }

    nullifierHash <== commitmentHasher.nullifierHash;
    root <== merkleTreeChecker.root;
}

component main {
    public [encryptedBalance,   
			pubKey]	
                } = nullifyDepositCommitment(20);