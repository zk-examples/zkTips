pragma circom 2.2.1;

include "../../node_modules/circomlib/circuits/mimcsponge.circom";

template createDepositCommitment() {
    signal input value;
    signal input secret;
    signal input nullifier;
    signal input commitment;
    
    component commitmentHasher = MiMCSponge(3, 220, 1);

    commitmentHasher.ins[0] <== value;
    commitmentHasher.ins[1] <== secret;
    commitmentHasher.ins[2] <== nullifier;
    commitmentHasher.k <== 0;

    commitment === commitmentHasher.outs[0];
}

component main {
        public [value,              // in TransferFrom
                commitment]         // is written to storage    
                } = createDepositCommitment();