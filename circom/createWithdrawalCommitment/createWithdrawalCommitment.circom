pragma circom 2.2.1;

include "../../node_modules/circomlib/circuits/mimcsponge.circom";
include "../binpower.circom";

template createWithdrawalCommitment() {
    signal input encryptedSenderBalance;
    signal input value;
    signal input secret;
    signal input nullifier;
    signal input authSecret;

	// public key: g, rand r, n
    signal input senderPubKey[3];
	
	// private key: l, mu, n
	signal input senderPrivKey[3];

    signal output commitment;
	signal output encryptedSenderValueSub;
    signal output authCommitment;

    // value cannot be negative
	assert(value > 0);

    component authCommitmentHasher = MiMCSponge(1, 220, 1);
    authCommitmentHasher.ins[0] <== authSecret;
    authCommitmentHasher.k <== 0;

    // identity verification
    authCommitment <== authCommitmentHasher.outs[0];
    
    component commitmentHasher = MiMCSponge(3, 220, 1);
    commitmentHasher.ins[0] <== value;
    commitmentHasher.ins[1] <== secret;
    commitmentHasher.ins[2] <== nullifier;
    commitmentHasher.k <== 0;

    commitment <== commitmentHasher.outs[0];

    // deciphering the current sender balance 
	component pow1 = Binpower();
	pow1.b <== encryptedSenderBalance;
	pow1.e <== senderPrivKey[0];
	pow1.modulo <== senderPrivKey[2] * senderPrivKey[2];

	signal senderBalance <-- (pow1.out - 1) / senderPrivKey[2] * senderPrivKey[1] % senderPrivKey[2];

	// checking that the current sender balance is greater than the payment amount
	assert(senderBalance >= value);

    // checking the value encryption for the sender
	component pow3 = Binpower();
	component pow4 = Binpower();

	pow3.b <== senderPubKey[0];
	pow3.e <== senderPubKey[2] - value;
	pow3.modulo <== senderPubKey[2] * senderPubKey[2];

	pow4.b <== senderPubKey[1];
	pow4.e <== senderPubKey[2];
	pow4.modulo <== senderPubKey[2] * senderPubKey[2];

	signal enSenderValueSub <-- (pow3.out * pow4.out) % (senderPubKey[2] * senderPubKey[2]);
	encryptedSenderValueSub <== enSenderValueSub;
}

component main = createWithdrawalCommitment();