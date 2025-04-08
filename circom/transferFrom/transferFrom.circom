pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/mimcsponge.circom";
include "../binpower.circom";

template TransferFrom() {
	signal input encryptedSpenderBalance;
	signal input value;
    signal input authSecret;

	// public key: g, rand r, n
	signal input holderPubKey[3];
	signal input spenderPubKey[3];
	signal input receiverPubKey[3];
	
	// private key: l, mu, n
	signal input spenderPrivKey[3];

	signal output encryptedHolderValueSub;
	signal output encryptedSpenderValueSub;
	signal output encryptedReceiverValueAdd;
    signal output authCommitment;

    component authCommitmentHasher = MiMCSponge(1, 220, 1);
    authCommitmentHasher.ins[0] <== authSecret;
    authCommitmentHasher.k <== 0;

    // identity verification
    authCommitment <== authCommitmentHasher.outs[0];
	
	// value cannot be negative
	assert(value > 0);
	
	// deciphering the current allowance balance 
	component pow1 = Binpower();
	
	pow1.b <== encryptedSpenderBalance;
	pow1.e <== spenderPrivKey[0];
	pow1.modulo <== spenderPrivKey[2] * spenderPrivKey[2];

	signal spenderBalance <-- (pow1.out - 1) / spenderPrivKey[2] * spenderPrivKey[1] % spenderPrivKey[2];

	// checking that the current allowance balance is greater than the payment amount
	assert(spenderBalance >= value);
	
	// checking the value encryption for the spender
	component pow3 = Binpower();
	component pow4 = Binpower();

	pow3.b <== spenderPubKey[0];
	pow3.e <== spenderPubKey[2] - value;
	pow3.modulo <== spenderPubKey[2] * spenderPubKey[2];

	pow4.b <== spenderPubKey[1];
	pow4.e <== spenderPubKey[2];
	pow4.modulo <== spenderPubKey[2] * spenderPubKey[2];

	signal enSpenderValueSub <-- (pow3.out * pow4.out) % (spenderPubKey[2] * spenderPubKey[2]);
	encryptedSpenderValueSub <== enSpenderValueSub;
	
	// checking the value encryption for the holder
	component pow5 = Binpower();
	component pow6 = Binpower();

	pow5.b <== holderPubKey[0];
	pow5.e <== holderPubKey[2] - value;
	pow5.modulo <== holderPubKey[2] * holderPubKey[2];

	pow6.b <== holderPubKey[1];
	pow6.e <== holderPubKey[2];
	pow6.modulo <== holderPubKey[2] * holderPubKey[2];

	signal enHolderValueSub <-- (pow5.out * pow6.out) % (holderPubKey[2] * holderPubKey[2]);
	encryptedHolderValueSub <== enHolderValueSub;

	// checking the value encryption for the receiver
	component pow7 = Binpower();
	component pow8 = Binpower();

	pow7.b <== receiverPubKey[0];
	pow7.e <== value;
	pow7.modulo <== receiverPubKey[2] * receiverPubKey[2];

	pow8.b <== receiverPubKey[1];
	pow8.e <== receiverPubKey[2];
	pow8.modulo <== receiverPubKey[2] * receiverPubKey[2];

	signal enReceiverValueAdd <-- (pow7.out * pow8.out) % (receiverPubKey[2] * receiverPubKey[2]);
	encryptedReceiverValueAdd <== enReceiverValueAdd;
}

// public data
component main { 
	public [encryptedSpenderBalance]
			} = TransferFrom();