import * as fs from "fs";
import { expect } from "chai";
import * as snarkjs from "snarkjs";
import paillierBigint from "paillier-bigint";

import { ZkTips } from "../../typechain-types";
import { getRandomBigInt } from "../common/common";

export async function createWithdrawalCommitment(
  zkTips: ZkTips,
  idFrom: number,
  value: string,
  secret: string,
  nullifier: string,
  authSecret: string,
  senderKeys: paillierBigint.KeyPair
) {
  const { proof, publicSignals } = await createWithdrawalProof(
    await zkTips.balanceOf(idFrom),
    value,
    secret,
    nullifier,
    authSecret,
    senderKeys
  );

  await expect(
    await zkTips.createWithdrawalCommitment(
      idFrom,
      [proof.pi_a[0], proof.pi_a[1]],
      [
        [proof.pi_b[0][1], proof.pi_b[0][0]],
        [proof.pi_b[1][1], proof.pi_b[1][0]],
      ],
      [proof.pi_c[0], proof.pi_c[1]],
      [publicSignals[0], publicSignals[1], publicSignals[2]]
    )
  ).to.emit(zkTips, "Commit");
}

export async function createWithdrawalProof(
  encryptedSenderBalance: bigint,
  value: string,
  secret: string,
  nullifier: string,
  authSecret: string,
  senderKeys: paillierBigint.KeyPair
) {
  return await snarkjs.groth16.fullProve(
    await getCommitmentData(
      encryptedSenderBalance,
      value,
      secret,
      nullifier,
      authSecret,
      senderKeys
    ),
    "test/createWithdrawalCommitment/createWithdrawalCommitment.wasm",
    "test/createWithdrawalCommitment/createWithdrawalCommitment.zkey"
  );
}

export async function verifyDepositProof(
  proof: snarkjs.Groth16Proof,
  publicSignals: snarkjs.PublicSignals
) {
  const vKey = JSON.parse(
    fs.readFileSync(
      "test/createWithdrawalCommitment/verification_key.json",
      "utf-8"
    )
  );

  return await snarkjs.groth16.verify(vKey, publicSignals, proof);
}

export async function getCommitmentData(
  encryptedSenderBalance: bigint,
  value: string,
  secret: string,
  nullifier: string,
  authSecret: string,
  senderKeys: paillierBigint.KeyPair
) {
  const sender_rand_r = getRandomBigInt(senderKeys.publicKey.n);

  const senderPubKey = [
    senderKeys.publicKey.g,
    sender_rand_r,
    senderKeys.publicKey.n,
  ];

  const senderPrivKey = [
    senderKeys.privateKey.lambda,
    senderKeys.privateKey.mu,
    senderKeys.privateKey.n,
  ];

  return {
    encryptedSenderBalance: encryptedSenderBalance,

    value: value,
    secret: secret,
    nullifier: nullifier,
    authSecret: authSecret,
    senderPubKey: senderPubKey,
    senderPrivKey: senderPrivKey,
  };
}
