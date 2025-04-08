import * as fs from "fs";
import * as snarkjs from "snarkjs";
import paillierBigint from "paillier-bigint";

import { ZkTips } from "../../typechain-types";
import { MiMC } from "../common/MiMC";
import { getRandomBigInt } from "../common/common";

export async function approve(
  zkTips: ZkTips,
  signer: any,
  holderKeys: paillierBigint.KeyPair,
  spenderKeys: paillierBigint.KeyPair,
  value: bigint,
  authSecret: string,
  holderID: bigint,
  spenderID: bigint
) {
  const mimcSponge = new MiMC();
  await mimcSponge.init();

  const { proof, publicSignals } = await approveProof(
    holderKeys,
    spenderKeys,
    value,
    await zkTips.balanceOf(holderID),
    authSecret
  );

  await zkTips.connect(signer).approve(
    holderID,
    spenderID,
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

export async function approveProof(
  holderKeys: paillierBigint.KeyPair,
  spenderKeys: paillierBigint.KeyPair,
  value: bigint,
  encryptedHolderBalance: bigint,
  authSecret: string
) {
  return await snarkjs.groth16.fullProve(
    getApproveData(
      holderKeys,
      spenderKeys,
      value,
      encryptedHolderBalance,
      authSecret
    ),
    "test/approve/approve.wasm",
    "test/approve/approve.zkey"
  );
}

export async function verifyApproveProof(
  proof: snarkjs.Groth16Proof,
  publicSignals: snarkjs.PublicSignals
) {
  const vKey = JSON.parse(
    fs.readFileSync("test/approve/verification_key.json", "utf-8")
  );

  return await snarkjs.groth16.verify(vKey, publicSignals, proof);
}

export function getApproveData(
  holderKeys: paillierBigint.KeyPair,
  spenderKeys: paillierBigint.KeyPair,
  value: bigint,
  encryptedHolderBalance: bigint,
  authSecret: string
) {
  const spender_rand_r = getRandomBigInt(spenderKeys.publicKey.n);
  const holder_rand_r = getRandomBigInt(holderKeys.publicKey.n);

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

  const holderPrivKey = [
    holderKeys.privateKey.lambda,
    holderKeys.privateKey.mu,
    holderKeys.privateKey.n,
  ];

  return {
    encryptedHolderBalance,
    value,
    authSecret,
    holderPubKey,
    spenderPubKey,
    holderPrivKey,
  };
}
