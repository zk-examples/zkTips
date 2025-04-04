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
import { SEED } from "./common/common";

describe("zkTips", function () {
  let signers: any[];
  let mimc: MimcSponge;
  let mimcsponge: any;
  let keysA: paillierBigint.KeyPair;
  let keysB: paillierBigint.KeyPair;

  async function deployFixture() {
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

  describe("snarkjs", function () {
    let nullifier: string;
    let secret: string;
    let value: string;
    let keys: paillierBigint.KeyPair;

    async function commitmentFixture() {
      nullifier = nullifier = BigInt(
        "0x" + crypto.randomBytes(31).toString("hex")
      ).toString();
      secret = BigInt("0x" + crypto.randomBytes(31).toString("hex")).toString();
      value = 100n.toString();
      keys = await paillierBigint.generateRandomKeys(32);
    }

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
