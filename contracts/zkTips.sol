// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IVerifiers.sol";
import "./MerkleTreeWithHistory.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract zkTips is MerkleTreeWithHistory {
    struct Key {
        uint256 g;
        uint256 n;
        uint256 powN2;
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
    mapping(uint256 => User) private users;

    mapping(bytes32 => bool) public nullifiers;
    mapping(bytes32 => bool) public commitments;

    uint ids;

    IERC20 public token;

    ICreateDepositCommitment private createDepositVerifier;
    INullifyDepositCommitment private nullifyDepositVerifier;
    ITransferVerifier private transferVerifier;

    // ICreateWithdrawCommitment private createWithdrawVerifier;
    // INullifyWithdrawCommitment private nullifWithdrawCommitmentVerifier;

    constructor(
        uint32 _levels,
        address _hasher,
        address _token,
        address _createDepositVerifierAddr,
        address _nullifyDepositVerifier,
        address _transferVerifier,
        address _createWithdrawVerifier,
        address _nullifWithdrawCommitmentVerifier
    ) MerkleTreeWithHistory(_levels, IHasher(_hasher)) {
        token = IERC20(_token);

        createDepositVerifier = ICreateDepositCommitment(
            _createDepositVerifierAddr
        );
        nullifyDepositVerifier = INullifyDepositCommitment(
            _nullifyDepositVerifier
        );
        transferVerifier = ITransferVerifier(_transferVerifier);
        // createWithdrawVerifier = ICreateWithdrawCommitment(
        //     _createWithdrawVerifier
        // );
        // nullifWithdrawCommitmentVerifier = INullifyWithdrawCommitment(
        //     _nullifWithdrawCommitmentVerifier
        // );
    }

    function createDepositCommitment(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[2] calldata input
    ) external {
        require(
            createDepositVerifier.verifyProof(a, b, c, input),
            "Invalid proof"
        );

        token.transferFrom(msg.sender, address(this), input[0] * 1e18);
        _commit(bytes32(input[1]));
    }

    function nullifyDepositCommitment(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[6] calldata input,
        uint256 authCommitment
    ) external {
        require(
            nullifyDepositVerifier.verifyProof(a, b, c, input),
            "Invalid proof"
        );
        require(
            !nullifiers[bytes32(input[0])],
            "The nullifier has been submitted"
        );
        require(isKnownRoot(bytes32(input[1])), "Cannot find your merkle root");

        nullifiers[bytes32(input[0])] = true;

        User memory user;
        user.authCommitment = bytes32(authCommitment);
        user.encryptedBalance = input[2];
        user.key.g = input[3];
        user.key.n = input[5];
        user.key.powN2 = input[5] * input[5];

        users[ids] = user;

        ids++;
    }

    function transferFrom(
        uint256 idFrom,
        uint256 idTo,
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[4] calldata input
    ) external {
        require(transferVerifier.verifyProof(a, b, c, input), "Invalid proof");

        User storage receiver = users[idTo];
        User storage sender = users[idFrom];

        require(bytes32(input[3]) == users[idFrom].authCommitment);

        unchecked {
            receiver.encryptedBalance =
                (receiver.encryptedBalance * input[2]) %
                receiver.key.powN2;

            sender.encryptedBalance =
                (sender.encryptedBalance * input[1]) %
                sender.key.powN2;
        }
    }

    function balanceOf(uint256 _id) external view returns (uint256) {
        return users[_id].encryptedBalance;
    }

    function getPubKey(uint256 _id) external view returns (Key memory) {
        return users[_id].key;
    }

    function _commit(bytes32 _commitment) internal {
        require(!commitments[_commitment], "The commitment has been submitted");
        commitments[_commitment] = true;
        uint32 insertedIndex = _insert(_commitment);
        emit Commit(_commitment, insertedIndex, block.timestamp);
    }
}
