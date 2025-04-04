pragma circom 2.1.6;

include "../binpower.circom";

template BalanceChecker() {
    signal input encryptedBalance;
	signal input balance;
	// public key: g, rand r, n
	signal input pubKey[3];

	// checking that the sender knows his balance and it is correct, you need to know r
	component pow1 = Binpower();
	component pow2 = Binpower();

	pow1.b <== pubKey[0];
	pow1.e <== balance;
	pow1.modulo <== pubKey[2] * pubKey[2];

	pow2.b <== pubKey[1];
	pow2.e <== pubKey[2];
	pow2.modulo <== pubKey[2] * pubKey[2];

	signal enBalance <-- (pow1.out * pow2.out) % (pubKey[2] * pubKey[2]);
	encryptedBalance === enBalance;
}