import * as fs from "fs";
import * as snarkjs from "snarkjs";
import { MerkleTree } from "fixed-merkle-tree";

import { MiMC } from "../common/MiMC";
import { ZkTips } from "../../typechain-types";

export async function nullifyWithdrawalCommitment(
  zkTips: ZkTips,
  value: string,
  secret: string,
  nullifier: string,
  tree: MerkleTree
) {
  const { proof, publicSignals } = await nullifyWithdrawalProof(
    value,
    secret,
    nullifier,
    tree
  );

  await zkTips.nullifyWithdrawalCommitment(
    [proof.pi_a[0], proof.pi_a[1]],
    [
      [proof.pi_b[0][1], proof.pi_b[0][0]],
      [proof.pi_b[1][1], proof.pi_b[1][0]],
    ],
    [proof.pi_c[0], proof.pi_c[1]],
    [publicSignals[0], publicSignals[1], publicSignals[2]]
  );
}

export async function nullifyWithdrawalProof(
  value: string,
  secret: string,
  nullifier: string,
  tree: MerkleTree
) {
  return await snarkjs.groth16.fullProve(
    await getNullifyWithdrawalCommitmentData(value, secret, nullifier, tree),
    "test/nullifyWithdrawalCommitment/nullifyWithdrawalCommitment.wasm",
    "test/nullifyWithdrawalCommitment/nullifyWithdrawalCommitment.zkey"
  );
}

export async function verifyNullifyWithdrawalProof(
  proof: snarkjs.Groth16Proof,
  publicSignals: snarkjs.PublicSignals
) {
  const vKey = JSON.parse(
    fs.readFileSync(
      "test/nullifyWithdrawalCommitment/verification_key.json",
      "utf-8"
    )
  );

  return await snarkjs.groth16.verify(vKey, publicSignals, proof);
}

export async function getNullifyWithdrawalCommitmentData(
  value: string,
  secret: string,
  nullifier: string,
  tree: MerkleTree
) {
  const mimcSponge = new MiMC();
  await mimcSponge.init();

  const commitment = mimcSponge.multiHash([value, secret, nullifier]);

  tree.insert(commitment);

  const proof = tree.proof(commitment);

  return {
    nullifier: nullifier,
    secret: secret,
    value: value,
    pathElements: proof.pathElements, // rootAndPath.pathElements,
    pathIndices: proof.pathIndices, //rootAndPath.pathIndices,
  };
}
