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
  transferAgregation,
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
import { approve, approveProof, verifyApproveProof } from "./approve/approve";
import { transferFrom, transferFromProof } from "./transferFrom/transferFrom";
import { createWithdrawalCommitment } from "./createWithdrawalCommitment/createWithdrawalCommitment";
import { nullifyWithdrawalCommitment } from "./nullifyWithdrawalCommitment/nullifyWithdrawalCommitment";

// npx hardhat test test\zkTips.test.ts
describe("zkTips", function () {
  let signers: any[];

  let mimcsponge: any; // contract
  let zkTips: ZkTips;
  let createDepositVerifier: any;
  let nullifyDepositVerifier: any;
  let transferVerifier: any;
  let approveVerifier: any;
  let transferFromVerifier: any;
  let createWithdrawVerifier: any;
  let nullifyWithdrawVerifier: any;
  let token: TestToken;

  let keysA: paillierBigint.KeyPair;
  let keysB: paillierBigint.KeyPair;
  let keysC: paillierBigint.KeyPair;
  let keys: paillierBigint.KeyPair;

  let mimcSponge: MiMC;
  let tree: MerkleTree;

  let nullifierA: string;
  let nullifierB: string;
  let nullifierC: string;
  let secretA: string;
  let secretB: string;
  let secretC: string;
  let value: string;
  const initBalance = hre.ethers.parseEther("1000");

  const hashFunction: HashFunction<Element> = (left, right) => {
    return mimcSponge.hash(left, right);
  };

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

    token = (await hre.ethers.deployContract("TestToken", [
      signers[0],
      signers[1],
      signers[2],
    ])) as unknown as TestToken;

    createDepositVerifier = await hre.ethers.deployContract(
      "CreateDepositCommitmentVerifier"
    );
    nullifyDepositVerifier = await hre.ethers.deployContract(
      "NullifyDepositCommitment"
    );
    transferVerifier = await hre.ethers.deployContract("TransferVerifier");
    approveVerifier = await hre.ethers.deployContract("ApproveVerifier");
    transferFromVerifier = await hre.ethers.deployContract(
      "TransferFromVerifier"
    );
    createWithdrawVerifier = await hre.ethers.deployContract(
      "CreateWithdrawCommitmentVerifier"
    );
    nullifyWithdrawVerifier = await hre.ethers.deployContract(
      "NullifyWithdrawalCommitmentVerifier"
    );

    zkTips = (await hre.ethers.deployContract("zkTips", [
      TREE_LEVELS,
      mimcspongeAddr,
      token.target,
      createDepositVerifier.target,
      nullifyDepositVerifier.target,
      transferVerifier.target,
      approveVerifier.target,
      transferFromVerifier.target,
      createWithdrawVerifier.target,
      nullifyWithdrawVerifier.target,
    ])) as unknown as ZkTips;

    keysA = await paillierBigint.generateRandomKeys(32);
    keysB = await paillierBigint.generateRandomKeys(32);
    keysC = await paillierBigint.generateRandomKeys(32);

    await token.connect(signers[0]).approve(zkTips.target, initBalance);
    await token.connect(signers[1]).approve(zkTips.target, initBalance);
    await token.connect(signers[2]).approve(zkTips.target, initBalance);

    nullifierA = getNullifierOrSecret();
    secretA = getNullifierOrSecret();
    nullifierB = getNullifierOrSecret();
    secretB = getNullifierOrSecret();
    nullifierC = getNullifierOrSecret();
    secretC = getNullifierOrSecret();

    value = 100n.toString();
    keys = await paillierBigint.generateRandomKeys(32);

    tree = new MerkleTree(TREE_LEVELS, undefined, {
      hashFunction,
      zeroElement: ZERO_VALUE,
    });
  }

  describe.skip("snarkjs", function () {
    it("Create Deposit Commitment", async function () {
      await loadFixture(deployFixture);

      const { proof, publicSignals } = await createDepositProof(
        value,
        secretA,
        nullifierA
      );

      const result = await verifyDepositProof(proof, publicSignals);

      expect(result).to.be.true;
    });

    it("Nullify Deposit Commitment", async function () {
      await loadFixture(deployFixture);

      const { proof, publicSignals } = await nullifyDepositProof(
        value,
        secretA,
        nullifierA,
        keys,
        tree
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

    it("Approve Proof", async function () {
      await loadFixture(deployFixture);

      const { proof, publicSignals } = await approveProof(
        keysA, // holder
        keysB, // spender
        BigInt(value), // value
        keysA.publicKey.encrypt(BigInt(value)), // encryptedHolderBalance
        secretA // authSecret
      );

      const authCommitment = mimcSponge.simpleHash(secretA);
      expect(authCommitment == publicSignals[3]).to.be.true;

      const valueA = keysA.privateKey.decrypt(BigInt(publicSignals[1]));
      const valueB = keysB.privateKey.decrypt(BigInt(publicSignals[2]));

      expect(valueA == BigInt(value)).to.be.true;
      expect(valueB == BigInt(value)).to.be.true;

      const result = await verifyApproveProof(proof, publicSignals);

      expect(result).to.be.true;
    });
  });

  describe("zkTips", function () {
    it("Deployed", async function () {
      await loadFixture(deployFixture);

      const balance0 = await token.balanceOf(signers[0]);
      const balance1 = await token.balanceOf(signers[1]);

      expect(balance0 == BigInt(initBalance)).to.be.true;
      expect(balance1 == BigInt(initBalance)).to.be.true;
    });

    it.skip("Create Deposit Commitment", async function () {
      await loadFixture(deployFixture);

      resetTree();

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

      resetTree();

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

    it.skip("Transfer", async function () {
      await loadFixture(deployFixture);

      await registrationABC();

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

    it.skip("Approve + IncreaseAllowance", async function () {
      await loadFixture(deployFixture);

      await registrationABC();

      const approveValue = 20n;

      await approve(
        zkTips,
        signers[0],
        keysA,
        keysB,
        approveValue,
        secretA,
        0n,
        1n
      );

      await approve(
        zkTips,
        signers[0],
        keysA,
        keysB,
        approveValue,
        secretA,
        0n,
        1n
      );

      expect(
        keysA.privateKey.decrypt(await zkTips.balanceOf(0)) ==
          BigInt(value) - approveValue * 2n
      ).to.be.true;

      const allowance = await zkTips.getAllowance(0, 1);

      expect(
        keysA.privateKey.decrypt(allowance.encryptedHolderBalance) ==
          approveValue * 2n
      ).to.be.true;

      expect(
        keysB.privateKey.decrypt(allowance.encryptedSpenderBalance) ==
          approveValue * 2n
      ).to.be.true;
    });

    it.skip("TransferFrom", async function () {
      await loadFixture(deployFixture);

      await registrationABC();

      const approveValue = 30n;
      const transferValue = 10n;

      await approve(
        zkTips,
        signers[0],
        keysA,
        keysB,
        approveValue,
        secretA,
        0n,
        1n
      );

      await transferFrom(
        zkTips,
        signers[1],
        keysA,
        keysB,
        keysC,
        transferValue,
        secretB,
        0n,
        1n,
        2n
      );

      expect(
        keysC.privateKey.decrypt(await zkTips.balanceOf(2)) ==
          BigInt(value) + transferValue
      ).to.be.true;

      const allowance = await zkTips.getAllowance(0, 1);

      expect(
        keysA.privateKey.decrypt(allowance.encryptedHolderBalance) ==
          approveValue - transferValue
      ).to.be.true;

      expect(
        keysB.privateKey.decrypt(allowance.encryptedSpenderBalance) ==
          approveValue - transferValue
      ).to.be.true;
    });

    it.skip("Transfer agregation", async function () {
      await loadFixture(deployFixture);

      await registrationABC();

      const transferValue = 1n;

      let balance = await zkTips.balanceOf(0);

      for (let i = 0n; i < 5n; i++) {
        balance = await transferAgregation(
          keysA,
          keysB,
          transferValue,
          secretA,
          i,
          balance
        );

        console.log(keysA.privateKey.decrypt(balance));
      }
    });

    it("Create + Nullify Withdrawal Commitment", async function () {
      await loadFixture(deployFixture);

      await registrationABC();

      nullifierA = getNullifierOrSecret();

      const withdrawValue = 15n;

      await createWithdrawalCommitment(
        zkTips,
        0,
        withdrawValue.toString(),
        secretB,
        nullifierA,
        secretA, // authSecret
        keysA
      );

      const balance = keysA.privateKey.decrypt(await zkTips.balanceOf(0));

      expect(balance == BigInt(value) - withdrawValue).to.be.true;

      const balanceTokenBefore = await token.balanceOf(signers[0]);

      await nullifyWithdrawalCommitment(
        zkTips,
        withdrawValue.toString(),
        secretB,
        nullifierA,
        tree
      );

      const balanceTokenAfter = await token.balanceOf(signers[0]);

      expect(
        balanceTokenBefore + hre.ethers.parseUnits(withdrawValue.toString()) ==
          balanceTokenAfter
      ).to.be.true;
    });
  });

  const registrationABC = async () => {
    resetTree();

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

    await createDepositCommitment(
      zkTips,
      signers[2],
      value,
      secretC,
      nullifierC
    );

    await nullifyDepositCommitment(
      zkTips,
      signers[2],
      value,
      secretC,
      nullifierC,
      keysC,
      mimcSponge.simpleHash(secretC),
      tree
    );
  };

  const resetTree = () => {
    tree = new MerkleTree(TREE_LEVELS, undefined, {
      hashFunction,
      zeroElement: ZERO_VALUE,
    });
  };
});
