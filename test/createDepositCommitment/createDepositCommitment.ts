import * as crypto from "crypto";
import * as fs from "fs";
import { buildMimcSponge } from "circomlibjs";
import * as snarkjs from "snarkjs";
import { MerkleTree, HashFunction, Element } from "fixed-merkle-tree";

export async function createDepositProof(
  nullifier: string,
  secret: string,
  value: string
) {
  return await snarkjs.groth16.fullProve(
    await getCommitmentData(nullifier, secret, value),
    "test/createDepositCommitment/createDepositCommitment.wasm",
    "test/createDepositCommitment/createDepositCommitment.zkey"
  );
}

export async function verifyDepositProof(
  proof: snarkjs.Groth16Proof,
  publicSignals: snarkjs.PublicSignals
) {
  const vKey = JSON.parse(
    fs.readFileSync(
      "test/createDepositCommitment/verification_key.json",
      "utf-8"
    )
  );

  return await snarkjs.groth16.verify(vKey, publicSignals, proof);
}

export async function getCommitmentData(
  nullifier: string,
  secret: string,
  value: string
) {
  const mimc = await buildMimcSponge();

  const commitment = mimc.F.toString(
    mimc.multiHash([value, secret, nullifier])
  );

  return {
    value: value,
    secret: secret,
    nullifier: nullifier,
    commitment: commitment,
  };
}
