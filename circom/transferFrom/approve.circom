pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/mimcsponge.circom";
include "../binpower.circom";

template Approve() {
	signal input encryptedHolderBalance;
	signal input value;
    signal input authSecret;

	// public key: g, rand r, n
	signal input holderPubKey[3];
	signal input spenderPubKey[3];
	
	// private key: l, mu, n
	signal input holderPrivKey[3];

	signal output encryptedHolderValueSub;
	signal output encryptedHolderValueAdd;
	signal output encryptedSpenderValue;
    signal output authCommitment;

    component authCommitmentHasher = MiMCSponge(1, 220, 1);
    authCommitmentHasher.ins[0] <== authSecret;
    authCommitmentHasher.k <== 0;

    // identity verification
    authCommitment <== authCommitmentHasher.outs[0];
	
	// value cannot be negative
	assert(value > 0);
	
	// deciphering the current holder balance 
	component pow1 = Binpower();
	
	pow1.b <== encryptedHolderBalance;
	pow1.e <== holderPrivKey[0];
	pow1.modulo <== holderPrivKey[2] * holderPrivKey[2];

	signal holderBalance <-- (pow1.out - 1) / holderPrivKey[2] * holderPrivKey[1] % holderPrivKey[2];

	// checking that the current holder balance is greater than the approve amount
	assert(holderBalance >= value);
	
	// checking the value encryption for the spender
	component pow3 = Binpower();
	component pow4 = Binpower();

	pow3.b <== spenderPubKey[0];
	pow3.e <== value;
	pow3.modulo <== spenderPubKey[2] * spenderPubKey[2];

	pow4.b <== spenderPubKey[1];
	pow4.e <== spenderPubKey[2];
	pow4.modulo <== spenderPubKey[2] * spenderPubKey[2];

	signal enSpenderValue <-- (pow3.out * pow4.out) % (spenderPubKey[2] * spenderPubKey[2]);
	encryptedSpenderValue <== enSpenderValue;
	
	// checking the value encryption for the holder
	component pow5 = Binpower();
	component pow6 = Binpower();

	pow5.b <== holderPubKey[0];
	pow5.e <== value;
	pow5.modulo <== holderPubKey[2] * holderPubKey[2];

	pow6.b <== holderPubKey[1];
	pow6.e <== holderPubKey[2];
	pow6.modulo <== holderPubKey[2] * holderPubKey[2];

	signal enHolderValueAdd <-- (pow5.out * pow6.out) % (holderPubKey[2] * holderPubKey[2]);
	encryptedHolderValueAdd <== enHolderValueAdd;

	component pow7 = Binpower();
	component pow8 = Binpower();

	pow7.b <== holderPubKey[0];
	pow7.e <== holderPubKey[2] - value;
	pow7.modulo <== holderPubKey[2] * holderPubKey[2];

	pow8.b <== holderPubKey[1];
	pow8.e <== holderPubKey[2];
	pow8.modulo <== holderPubKey[2] * holderPubKey[2];

	signal enHolderValueSub <-- (pow7.out * pow8.out) % (holderPubKey[2] * holderPubKey[2]);
	encryptedHolderValueSub <== enHolderValueSub;
}

// public data
component main { 
	public [encryptedHolderBalance]
			} = Approve();