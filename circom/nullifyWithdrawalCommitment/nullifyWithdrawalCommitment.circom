pragma circom 2.1.6;

include "commitmentHasher.circom";
include "merkleTreeChecker.circom";

template nullifyWithdrawalCommitment(levels) {
    signal input nullifier;
    signal input secret;
    signal input value;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    signal output nullifierHash;
    signal output root;

    component commitmentHasher = CommitmentHasher();
    component merkleTreeChecker = MerkleTreeChecker(levels);

    commitmentHasher.nullifier <== nullifier;
    commitmentHasher.secret <== secret;
    commitmentHasher.value <== value;

    merkleTreeChecker.leaf <== commitmentHasher.commitment;
    for (var i = 0; i < levels; i++) {
        merkleTreeChecker.pathElements[i] <== pathElements[i];
        merkleTreeChecker.pathIndices[i] <== pathIndices[i];
    }

    nullifierHash <== commitmentHasher.nullifierHash;
    root <== merkleTreeChecker.root;
}

component main {public [value]} = nullifyWithdrawalCommitment(20);