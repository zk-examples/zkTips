import * as fs from "fs";
import * as snarkjs from "snarkjs";
import paillierBigint from "paillier-bigint";

import { getRandomBigInt } from "../common/common";

export async function transferProof(
  senderKeys: paillierBigint.KeyPair,
  receiverKeys: paillierBigint.KeyPair,
  value: bigint,
  encryptedSenderBalance: bigint,
  authCommitment: bigint,
  authSecret: bigint
) {
  return await snarkjs.groth16.fullProve(
    getTransferData(
      senderKeys,
      receiverKeys,
      value,
      encryptedSenderBalance,
      authCommitment,
      authSecret
    ),
    "test/transfer/transfer.wasm",
    "test/transfer/transfer.zkey"
  );
}

export async function verifyTransferProof(
  proof: snarkjs.Groth16Proof,
  publicSignals: snarkjs.PublicSignals
) {
  const vKey = JSON.parse(
    fs.readFileSync("test/transfer/verification_key.json", "utf-8")
  );

  return await snarkjs.groth16.verify(vKey, publicSignals, proof);
}

export function getTransferData(
  senderKeys: paillierBigint.KeyPair,
  receiverKeys: paillierBigint.KeyPair,
  value: bigint,
  encryptedSenderBalance: bigint,
  authCommitment: bigint,
  authSecret: bigint
) {
  const sender_rand_r = getRandomBigInt(senderKeys.publicKey.n);
  const receiver_rand_r = getRandomBigInt(receiverKeys.publicKey.n);
  const encryptedSenderValue = senderKeys.publicKey.encrypt(
    senderKeys.publicKey.n - value,
    sender_rand_r
  );
  const encryptedReceiverValue = receiverKeys.publicKey.encrypt(
    value,
    receiver_rand_r
  );
  const senderPubKey = [
    senderKeys.publicKey.g,
    sender_rand_r,
    senderKeys.publicKey.n,
  ];
  const receiverPubKey = [
    receiverKeys.publicKey.g,
    receiver_rand_r,
    receiverKeys.publicKey.n,
  ];
  const senderPrivKey = [
    senderKeys.privateKey.lambda,
    senderKeys.privateKey.mu,
    senderKeys.privateKey.n,
  ];

  return {
    encryptedSenderBalance,
    encryptedSenderValue,
    encryptedReceiverValue,
    value,
    authCommitment,
    authSecret,
    senderPubKey,
    receiverPubKey,
    senderPrivKey,
  };
}
