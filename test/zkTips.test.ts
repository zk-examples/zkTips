import {
  time,
  loadFixture,
} from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { assert, expect } from "chai";
import hre from "hardhat";
import * as crypto from "crypto";

import * as snarkjs from "snarkjs";

import { buildMimcSponge, MimcSponge, mimcSpongecontract } from "circomlibjs";
import paillierBigint from "paillier-bigint";

import {
  createDepositProof,
  verifyDepositProof,
} from "./createDepositCommitment/createDepositCommitment";
import {
  nullifyDepositProof,
  verifyNullifyDepositProof,
} from "./nullifyDepositCommitment/nullifyDepositCommitment";

import { transferProof, verifyTransferProof } from "./transfer/transfer";

import { SEED } from "./common/common";
import { MiMC } from "./common/MiMC";

describe("zkTips", function () {
  let signers: any[];
  let mimc: MimcSponge;
  let mimcsponge: any;
  let keysA: paillierBigint.KeyPair;
  let keysB: paillierBigint.KeyPair;
  let mimcSponge: MiMC;
  let nullifier: string;
  let secret: string;
  let value: string;
  let keys: paillierBigint.KeyPair;

  async function deployFixture() {
    mimcSponge = new MiMC();
    await mimcSponge.init();

    signers = await hre.ethers.getSigners();

    const MiMCSponge = new hre.ethers.ContractFactory(
      mimcSpongecontract.abi,
      mimcSpongecontract.createCode(SEED, 220),
      signers[0]
    );
    mimcsponge = await MiMCSponge.deploy();
    await mimcsponge.waitForDeployment();
    const mimcspongeAddr = (await mimcsponge.getAddress()) as string;

    mimc = await buildMimcSponge();

    keysA = await paillierBigint.generateRandomKeys(32);
    keysB = await paillierBigint.generateRandomKeys(32);
  }

  async function commitmentFixture() {
    nullifier = nullifier = BigInt(
      "0x" + crypto.randomBytes(31).toString("hex")
    ).toString();
    secret = BigInt("0x" + crypto.randomBytes(31).toString("hex")).toString();
    value = 100n.toString();
    keys = await paillierBigint.generateRandomKeys(32);
  }

  describe("snarkjs", function () {
    it("Create Deposit Commitment", async function () {
      await loadFixture(commitmentFixture);

      const { proof, publicSignals } = await createDepositProof(
        nullifier,
        secret,
        value
      );

      const result = await verifyDepositProof(proof, publicSignals);

      expect(result).to.be.true;
    });

    it("Nullify Deposit Commitment", async function () {
      await loadFixture(commitmentFixture);

      const { proof, publicSignals } = await nullifyDepositProof(
        value,
        secret,
        nullifier,
        keys
      );

      const balance = keys.privateKey.decrypt(BigInt(publicSignals[2]));

      expect(balance == BigInt(value)).to.be.true;

      const result = await verifyNullifyDepositProof(proof, publicSignals);

      expect(result).to.be.true;
    });

    it("Transfer Proof", async function () {
      await loadFixture(deployFixture);

      const { proof, publicSignals } = await transferProof(
        keysA,
        keysB,
        BigInt(value),
        keysA.publicKey.encrypt(BigInt(value)),
        BigInt(mimcSponge.simpleHash(secret)),
        BigInt(secret)
      );

      const valueA = keysA.privateKey.decrypt(BigInt(publicSignals[0]));
      const valueB = keysB.privateKey.decrypt(BigInt(publicSignals[2]));

      expect(valueA == BigInt(value)).to.be.true;
      expect(valueB == BigInt(value)).to.be.true;

      expect(publicSignals[3] == mimcSponge.simpleHash(secret)).to.be.true;

      const result = await verifyTransferProof(proof, publicSignals);

      expect(result).to.be.true;
    });
  });

  describe("External contracts", function () {
    // it("Checking MiMC hash()", async function () {
    //   // await loadFixture(deployContracts);
    //   const res = await mimcsponge["MiMCSponge"](1, 2, 3);
    //   const res2 = mimc.hash(1, 2, 3);
    //   assert.equal(res.xL.toString(), mimc.F.toString(res2.xL));
    //   assert.equal(res.xR.toString(), mimc.F.toString(res2.xR));
    // });
  });
});
