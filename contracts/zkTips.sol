// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IVerifiers.sol";
import "./MerkleTreeWithHistory.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract zkTips is MerkleTreeWithHistory {
    struct Key {
        uint g;
        uint n;
        uint powN2;
    }

    struct User {
        uint encryptedBalance;
        Key key;
        bytes32 authCommitment;
    }

    event Commit(
        bytes32 indexed commitment,
        uint32 leafIndex,
        uint256 timestamp
    );

    // ID - User
    mapping(uint => User) private users;

    mapping(bytes32 => bool) public nullifiers;
    mapping(bytes32 => bool) public commitments;

    uint ids;

    IERC20 public token;

    ICreateDepositCommitment private createDepositVerifier;

    // INullifyDepositCommitment private nullifyDepositCommitmentVerifier;
    // ITransfer private transferVerifier;
    // ICreateWithdrawCommitment private createWithdrawVerifier;
    // INullifyWithdrawCommitment private nullifWithdrawCommitmentVerifier;

    constructor(
        uint32 _levels,
        address _hasher,
        address _token,
        address _createDepositVerifierAddr,
        address _nullifyDepositCommitmentVerifier,
        address _transferVerifier,
        address _createWithdrawVerifier,
        address _nullifWithdrawCommitmentVerifier
    ) MerkleTreeWithHistory(_levels, IHasher(_hasher)) {
        token = IERC20(_token);

        createDepositVerifier = ICreateDepositCommitment(
            _createDepositVerifierAddr
        );
        // nullifyDepositCommitmentVerifier = INullifyDepositCommitment(
        //     _nullifyDepositCommitmentVerifier
        // );
        // transferVerifier = ITransfer(_transferVerifier);
        // createWithdrawVerifier = ICreateWithdrawCommitment(
        //     _createWithdrawVerifier
        // );
        // nullifWithdrawCommitmentVerifier = INullifyWithdrawCommitment(
        //     _nullifWithdrawCommitmentVerifier
        // );
    }

    function createDepositCommitment(
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[2] calldata input
    ) external {
        require(
            createDepositVerifier.verifyProof(a, b, c, input),
            "Invalid proof"
        );

        token.transferFrom(msg.sender, address(this), input[0]);
        _commit(bytes32(input[1]));
    }

    function _commit(bytes32 _commitment) internal {
        require(!commitments[_commitment], "The commitment has been submitted");
        commitments[_commitment] = true;
        uint32 insertedIndex = _insert(_commitment);
        emit Commit(_commitment, insertedIndex, block.timestamp);
    }
}
