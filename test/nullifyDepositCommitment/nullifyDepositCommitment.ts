import * as fs from "fs";
import { buildMimcSponge } from "circomlibjs";
import * as snarkjs from "snarkjs";
import { getRandomBigInt, toFixedHex, TREE_LEVELS } from "../common/common";

import paillierBigint from "paillier-bigint";
import { MerkleTree, HashFunction, Element } from "fixed-merkle-tree";
import { MiMC } from "../common/MiMC";

export async function nullifyDepositProof(
  value: string,
  secret: string,
  nullifier: string,
  keys: paillierBigint.KeyPair
) {
  return await snarkjs.groth16.fullProve(
    await getNullifyDepositCommitmentData(value, secret, nullifier, keys),
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
  keys: paillierBigint.KeyPair
) {
  const mimc = await buildMimcSponge();

  const mimcSponge = new MiMC();
  await mimcSponge.init();

  const hashFunction: HashFunction<Element> = (left, right) => {
    return mimcSponge.hash(left, right);
  };

  const tree = new MerkleTree(TREE_LEVELS, undefined, {
    hashFunction,
    zeroElement: "0",
  });

  const commitment = mimc.F.toString(
    mimc.multiHash([value, secret, nullifier])
  );

  tree.insert(toFixedHex(commitment));

  const proof = tree.path(0);

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
