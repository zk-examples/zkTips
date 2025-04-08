import * as fs from "fs";
import * as snarkjs from "snarkjs";
import paillierBigint from "paillier-bigint";

import { ZkTips } from "../../typechain-types";
import { MiMC } from "../common/MiMC";
import { getRandomBigInt } from "../common/common";

export async function transferFrom(
  zkTips: ZkTips,
  signer: any,
  holderKeys: paillierBigint.KeyPair,
  spenderKeys: paillierBigint.KeyPair,
  receiverKeys: paillierBigint.KeyPair,
  value: bigint,
  authSecret: string,
  holderID: bigint,
  spenderID: bigint,
  receiverID: bigint
) {
  const mimcSponge = new MiMC();
  await mimcSponge.init();

  const { proof, publicSignals } = await transferFromProof(
    holderKeys,
    spenderKeys,
    receiverKeys,
    value,
    (
      await zkTips.getAllowance(holderID, spenderID)
    ).encryptedSpenderBalance,
    authSecret
  );

  await zkTips.connect(signer).transferFrom(
    holderID,
    spenderID,
    receiverID,
    [proof.pi_a[0], proof.pi_a[1]],
    [
      [proof.pi_b[0][1], proof.pi_b[0][0]],
      [proof.pi_b[1][1], proof.pi_b[1][0]],
    ],
    [proof.pi_c[0], proof.pi_c[1]],
    [
      publicSignals[0],
      publicSignals[1],
      publicSignals[2],
      publicSignals[3],
      publicSignals[4],
    ]
  );
}

export async function transferFromProof(
  holderKeys: paillierBigint.KeyPair,
  spenderKeys: paillierBigint.KeyPair,
  receiverKeys: paillierBigint.KeyPair,
  value: bigint,
  encryptedSpenderBalance: bigint,
  authSecret: string
) {
  return await snarkjs.groth16.fullProve(
    getTransferFromData(
      holderKeys,
      spenderKeys,
      receiverKeys,
      value,
      encryptedSpenderBalance,
      authSecret
    ),
    "test/transferFrom/transferFrom.wasm",
    "test/transferFrom/transferFrom.zkey"
  );
}

export async function verifyTransferFromProof(
  proof: snarkjs.Groth16Proof,
  publicSignals: snarkjs.PublicSignals
) {
  const vKey = JSON.parse(
    fs.readFileSync("test/transferFrom/verification_key.json", "utf-8")
  );

  return await snarkjs.groth16.verify(vKey, publicSignals, proof);
}

export function getTransferFromData(
  holderKeys: paillierBigint.KeyPair,
  spenderKeys: paillierBigint.KeyPair,
  receiverKeys: paillierBigint.KeyPair,
  value: bigint,
  encryptedSpenderBalance: bigint,
  authSecret: string
) {
  const spender_rand_r = getRandomBigInt(spenderKeys.publicKey.n);
  const holder_rand_r = getRandomBigInt(holderKeys.publicKey.n);
  const receiver_rand_r = getRandomBigInt(receiverKeys.publicKey.n);

  const holderPubKey = [
    holderKeys.publicKey.g,
    spender_rand_r,
    holderKeys.publicKey.n,
  ];

  const spenderPubKey = [
    spenderKeys.publicKey.g,
    holder_rand_r,
    spenderKeys.publicKey.n,
  ];

  const receiverPubKey = [
    receiverKeys.publicKey.g,
    receiver_rand_r,
    receiverKeys.publicKey.n,
  ];

  const spenderPrivKey = [
    spenderKeys.privateKey.lambda,
    spenderKeys.privateKey.mu,
    spenderKeys.privateKey.n,
  ];

  return {
    encryptedSpenderBalance,
    value,
    authSecret,
    holderPubKey,
    spenderPubKey,
    receiverPubKey,
    spenderPrivKey,
  };
}
