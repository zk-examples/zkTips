import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { mimcSpongecontract } from "circomlibjs";
import paillierBigint from "paillier-bigint";
import { expect } from "chai";
import hre from "hardhat";

import {
  createDepositCommitment,
  createDepositProof,
  verifyDepositProof,
} from "./createDepositCommitment/createDepositCommitment";
import {
  nullifyDepositCommitment,
  nullifyDepositProof,
  verifyNullifyDepositProof,
} from "./nullifyDepositCommitment/nullifyDepositCommitment";

import {
  transfer,
  transferProof,
  verifyTransferProof,
} from "./transfer/transfer";

import {
  getNullifierOrSecret,
  SEED,
  TREE_LEVELS,
  ZERO_VALUE,
} from "./common/common";
import { MiMC } from "./common/MiMC";
import { TestToken, ZkTips } from "../typechain-types";
import MerkleTree, { HashFunction, Element } from "fixed-merkle-tree";

// npx hardhat test test\zkTips.test.ts
describe("zkTips", function () {
  let signers: any[];

  let mimcsponge: any; // contract
  let zkTips: ZkTips;
  let createDepositVerifier: any;
  let nullifyDepositVerifier: any;
  let transferVerifier: any;
  let token: TestToken;

  let keysA: paillierBigint.KeyPair;
  let keysB: paillierBigint.KeyPair;
  let keys: paillierBigint.KeyPair;

  let mimcSponge: MiMC;
  let tree: MerkleTree;

  let nullifierA: string;
  let nullifierB: string;
  let secretA: string;
  let secretB: string;
  let value: string;
  const initBalance = hre.ethers.parseEther("1000");

  async function deployFixture() {
    mimcSponge = new MiMC();
    await mimcSponge.init();

    const hashFunction: HashFunction<Element> = (left, right) => {
      return mimcSponge.hash(left, right);
    };

    tree = new MerkleTree(TREE_LEVELS, undefined, {
      hashFunction,
      zeroElement: ZERO_VALUE,
    });

    signers = await hre.ethers.getSigners();

    const MiMCSponge = new hre.ethers.ContractFactory(
      mimcSpongecontract.abi,
      mimcSpongecontract.createCode(SEED, 220),
      signers[0]
    );
    mimcsponge = await MiMCSponge.deploy();
    await mimcsponge.waitForDeployment();
    const mimcspongeAddr = (await mimcsponge.getAddress()) as string;

    token = (await hre.ethers.deployContract("TestToken", [
      signers[0],
      signers[1],
    ])) as unknown as TestToken;

    createDepositVerifier = await hre.ethers.deployContract(
      "CreateDepositCommitmentVerifier"
    );
    nullifyDepositVerifier = await hre.ethers.deployContract(
      "NullifyDepositCommitment"
    );
    transferVerifier = await hre.ethers.deployContract("TransferVerifier");

    zkTips = (await hre.ethers.deployContract("zkTips", [
      TREE_LEVELS,
      mimcspongeAddr,
      token.target,

      createDepositVerifier.target,
      nullifyDepositVerifier.target,
      transferVerifier.target,
      transferVerifier.target,
      transferVerifier.target,
    ])) as unknown as ZkTips;

    keysA = await paillierBigint.generateRandomKeys(32);
    keysB = await paillierBigint.generateRandomKeys(32);

    await token.connect(signers[0]).approve(zkTips.target, initBalance);
    await token.connect(signers[1]).approve(zkTips.target, initBalance);

    commitmentFixture();
  }

  async function commitmentFixture() {
    nullifierA = getNullifierOrSecret();
    secretA = getNullifierOrSecret();
    value = 100n.toString();
    keys = await paillierBigint.generateRandomKeys(32);
    nullifierB = getNullifierOrSecret();
    secretB = getNullifierOrSecret();
  }

  describe.skip("snarkjs", function () {
    it("Create Deposit Commitment", async function () {
      await loadFixture(commitmentFixture);

      const { proof, publicSignals } = await createDepositProof(
        value,
        secretA,
        nullifierA
      );

      const result = await verifyDepositProof(proof, publicSignals);

      expect(result).to.be.true;
    });

    it("Nullify Deposit Commitment", async function () {
      await loadFixture(commitmentFixture);

      const { proof, publicSignals } = await nullifyDepositProof(
        value,
        secretA,
        nullifierA,
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
        BigInt(mimcSponge.simpleHash(secretA)),
        BigInt(secretA)
      );

      const valueA = keysA.privateKey.decrypt(BigInt(publicSignals[0]));
      const valueB = keysB.privateKey.decrypt(BigInt(publicSignals[2]));

      expect(valueA == BigInt(value)).to.be.true;
      expect(valueB == BigInt(value)).to.be.true;

      expect(publicSignals[3] == mimcSponge.simpleHash(secretA)).to.be.true;

      const result = await verifyTransferProof(proof, publicSignals);

      expect(result).to.be.true;
    });
  });

  describe("zkTips", function () {
    it.skip("Deployed", async function () {
      await loadFixture(deployFixture);

      const balance0 = await token.balanceOf(signers[0]);
      const balance1 = await token.balanceOf(signers[1]);

      expect(balance0 == BigInt(initBalance)).to.be.true;
      expect(balance1 == BigInt(initBalance)).to.be.true;
    });

    it.skip("Create Deposit Commitment", async function () {
      await loadFixture(deployFixture);

      const balanceBefore = await token.balanceOf(signers[0]);

      const commitment = mimcSponge.multiHash([value, secretA, nullifierA]);

      tree.insert(commitment);

      await createDepositCommitment(
        zkTips,
        signers[0],
        value,
        secretA,
        nullifierA
      );

      const balanceAfer = await token.balanceOf(signers[0]);

      expect(balanceBefore - hre.ethers.parseUnits(value) == balanceAfer).to.be
        .true;

      expect(BigInt(tree.root) == BigInt(await zkTips.getLastRoot())).to.be
        .true;
    });

    it.skip("Nullify Deposit Commitment", async function () {
      await loadFixture(deployFixture);

      await createDepositCommitment(
        zkTips,
        signers[0],
        value,
        secretA,
        nullifierA
      );

      await nullifyDepositCommitment(
        zkTips,
        signers[0],
        value,
        secretA,
        nullifierA,
        keysA,
        mimcSponge.simpleHash(secretA),
        tree
      );

      const pubKey = await zkTips.getPubKey(0);

      expect(pubKey[0] == keysA.publicKey.g).to.be.true;
      expect(pubKey[1] == keysA.publicKey.n).to.be.true;
      expect(pubKey[2] == keysA.publicKey._n2).to.be.true;
      expect(
        keysA.privateKey.decrypt(await zkTips.balanceOf(0)).toString() == value
      ).to.be.true;
    });

    it("Transfer", async function () {
      await loadFixture(deployFixture);

      await createDepositCommitment(
        zkTips,
        signers[0],
        value,
        secretA,
        nullifierA
      );

      await nullifyDepositCommitment(
        zkTips,
        signers[0],
        value,
        secretA,
        nullifierA,
        keysA,
        mimcSponge.simpleHash(secretA),
        tree
      );

      await createDepositCommitment(
        zkTips,
        signers[1],
        value,
        secretB,
        nullifierB
      );

      await nullifyDepositCommitment(
        zkTips,
        signers[1],
        value,
        secretB,
        nullifierB,
        keysB,
        mimcSponge.simpleHash(secretB),
        tree
      );

      const transferValue = 20n;

      expect(
        keysA.privateKey.decrypt(await zkTips.balanceOf(0)).toString() == value
      ).to.be.true;

      expect(
        keysB.privateKey.decrypt(await zkTips.balanceOf(1)).toString() == value
      ).to.be.true;

      await transfer(
        zkTips,
        signers[0],
        keysA,
        keysB,
        transferValue,
        secretA,
        0n,
        1n
      );

      expect(
        keysA.privateKey.decrypt(await zkTips.balanceOf(0)) ==
          BigInt(value) - transferValue
      ).to.be.true;

      expect(
        keysB.privateKey.decrypt(await zkTips.balanceOf(1)) ==
          BigInt(value) + transferValue
      ).to.be.true;
    });
  });
});
