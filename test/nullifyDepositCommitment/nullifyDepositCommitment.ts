import * as fs from "fs";
import * as snarkjs from "snarkjs";
import paillierBigint from "paillier-bigint";
import { MerkleTree, HashFunction, Element } from "fixed-merkle-tree";

import { MiMC } from "../common/MiMC";
import { ZkTips } from "../../typechain-types";
import { getRandomBigInt, TREE_LEVELS, ZERO_VALUE } from "../common/common";

export async function nullifyDepositCommitment(
  zkTips: ZkTips,
  signer: any,
  value: string,
  secret: string,
  nullifier: string,
  keys: paillierBigint.KeyPair,
  authCommitment: string,
  id: bigint,
  tree: MerkleTree
) {
  const { proof, publicSignals } = await nullifyDepositProof(
    value,
    secret,
    nullifier,
    keys,
    tree
  );

  await zkTips.connect(signer).nullifyDepositCommitment(
    [proof.pi_a[0], proof.pi_a[1]],
    [
      [proof.pi_b[0][1], proof.pi_b[0][0]],
      [proof.pi_b[1][1], proof.pi_b[1][0]],
    ],
    [proof.pi_c[0], proof.pi_c[1]],
    publicSignals,
    authCommitment,
    id
  );
}

export async function nullifyDepositProof(
  value: string,
  secret: string,
  nullifier: string,
  keys: paillierBigint.KeyPair,
  tree: MerkleTree
) {
  return await snarkjs.groth16.fullProve(
    await getNullifyDepositCommitmentData(value, secret, nullifier, keys, tree),
    "test/nullifyDepositCommitment/nullifyDepositCommitment.wasm",
    "test/nullifyDepositCommitment/nullifyDepositCommitment.zkey"
  );
}

export async function verifyNullifyDepositProof(
  proof: snarkjs.Groth16Proof,
  publicSignals: snarkjs.PublicSignals
) {
  const vKey = JSON.parse(
    fs.readFileSync(
      "test/nullifyDepositCommitment/verification_key.json",
      "utf-8"
    )
  );

  return await snarkjs.groth16.verify(vKey, publicSignals, proof);
}

export async function getNullifyDepositCommitmentData(
  value: string,
  secret: string,
  nullifier: string,
  keys: paillierBigint.KeyPair,
  tree: MerkleTree
) {
  const mimcSponge = new MiMC();
  await mimcSponge.init();

  const commitment = mimcSponge.multiHash([value, secret, nullifier]);

  tree.insert(commitment);

  const proof = tree.proof(commitment);

  const r = getRandomBigInt(keys.publicKey.n);

  const balance = keys.publicKey.encrypt(BigInt(value), r);

  return {
    nullifier: nullifier,
    secret: secret,
    value: value,
    pathElements: proof.pathElements, // rootAndPath.pathElements,
    pathIndices: proof.pathIndices, //rootAndPath.pathIndices,
    encryptedBalance: balance,
    pubKey: [keys.publicKey.g, r, keys.publicKey.n],
  };
}
