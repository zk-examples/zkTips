import * as fs from "fs";
import { buildMimcSponge } from "circomlibjs";
import * as snarkjs from "snarkjs";
import { ZkTips } from "../../typechain-types";

export async function createDepositCommitment(
  zkTips: ZkTips,
  signer: any,
  value: string,
  secret: string,
  nullifier: string
) {
  const { proof, publicSignals } = await createDepositProof(
    value,
    secret,
    nullifier
  );

  await zkTips.connect(signer).createDepositCommitment(
    [proof.pi_a[0], proof.pi_a[1]],
    [
      [proof.pi_b[0][1], proof.pi_b[0][0]],
      [proof.pi_b[1][1], proof.pi_b[1][0]],
    ],
    [proof.pi_c[0], proof.pi_c[1]],
    [publicSignals[0], publicSignals[1]]
  );
}

export async function createDepositProof(
  value: string,
  secret: string,
  nullifier: string
) {
  return await snarkjs.groth16.fullProve(
    await getCommitmentData(value, secret, nullifier),
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
  value: string,
  secret: string,
  nullifier: string
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
