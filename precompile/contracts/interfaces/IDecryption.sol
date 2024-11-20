// Copyright 2021-2022, Offchain Labs, Inc.
// For license information, see https://github.com/OffchainLabs/nitro-contracts/blob/main/LICENSE
// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.24;

/// @title Provides aggregators and their users methods for configuring how they participate in L1 aggregation.
/// @notice Precompiled contract 
interface IDecryption {
    function getPK() external view returns (bytes memory);
    function setPK(bytes calldata _pk) external returns (bool);
    function decrypt(bytes calldata privateKeyByte, bytes calldata cipherBytes, string calldata id) external view returns (bytes memory);
    function verify(bytes calldata privateKeyByte, string calldata id) external view returns (bool);
}
