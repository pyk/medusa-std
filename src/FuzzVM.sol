// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

/**
 * @title FuzzVM Cheatcodes Interface
 * @notice Provides cheatcodes to manipulate EVM state and blockchain behavior during fuzzing.
 * @dev The cheatcode contract is deployed at 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D.
 * @custom:url https://secure-contracts.com/program-analysis/medusa/docs/src/cheatcodes/cheatcodes_overview.html
 */
interface FuzzVM {
    /**
     * @notice Sets the `block.timestamp`.
     * @param newTimestamp The new timestamp value.
     */
    function warp(uint256 newTimestamp) external;

    /**
     * @notice Sets the `block.number`.
     * @param newBlockNumber The new block number value.
     */
    function roll(uint256 newBlockNumber) external;

    /**
     * @notice Sets the `block.basefee`.
     * @param newBasefee The new basefee value.
     */
    function fee(uint256 newBasefee) external;

    /**
     * @notice Sets the `block.prevrandao`.
     * @param newPrevrandao The new prevrandao value.
     */
    function prevrandao(bytes32 newPrevrandao) external;

    /**
     * @notice Sets the `block.chainid`.
     * @param newChainId The new chain ID value.
     */
    function chainId(uint256 newChainId) external;

    /**
     * @notice Sets the `block.coinbase`.
     * @param newCoinbase The new coinbase address.
     */
    function coinbase(address newCoinbase) external;

    /**
     * @notice Loads a storage slot from an address.
     * @param account The target account address.
     * @param slot The storage slot to load.
     * @return value The value stored at the specified slot.
     */
    function load(address account, bytes32 slot) external returns (bytes32 value);

    /**
     * @notice Stores a value to an address' storage slot.
     * @param account The target account address.
     * @param slot The storage slot to modify.
     * @param value The value to store.
     */
    function store(address account, bytes32 slot, bytes32 value) external;

    /**
     * @notice Sets the `msg.sender` for the *next* call only.
     * @dev Calling the cheatcode contract itself counts as the next call.
     * @param sender The address to set as `msg.sender` for the next call.
     */
    function prank(address sender) external;

    /**
     * @notice Sets `msg.sender` for all subsequent calls until `stopPrank` is called.
     * @param sender The address to set as `msg.sender`.
     */
    function startPrank(address sender) external;

    /**
     * @notice Stops an active prank started by `startPrank`, resetting `msg.sender`.
     */
    function stopPrank() external;

    /**
     * @notice Sets `msg.sender` to the input address until the current call context exits.
     * @dev Persists across multiple calls within the same external function execution.
     * @param sender The address to set as `msg.sender`.
     */
    function prankHere(address sender) external;

    /**
     * @notice Sets an address's ETH balance.
     * @param who The address whose balance will be set.
     * @param newBalance The new balance in wei.
     */
    function deal(address who, uint256 newBalance) external;

    /**
     * @notice Sets an address's bytecode.
     * @param who The address whose code will be set.
     * @param code The new bytecode to deploy at the address.
     */
    function etch(address who, bytes calldata code) external;

    /**
     * @notice Signs a digest using a private key.
     * @param privateKey The private key to sign with.
     * @param digest The 32-byte hash digest to sign.
     * @return v The recovery ID.
     * @return r The R value of the signature.
     * @return s The S value of the signature.
     */
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);

    /**
     * @notice Computes the Ethereum address associated with a given private key.
     * @param privateKey The private key.
     * @return addr The computed address.
     */
    function addr(uint256 privateKey) external returns (address addr);

    /**
     * @notice Gets the creation bytecode of a contract.
     * @param contractPath The path to the contract file (e.g., "MyContract.sol").
     * @return code The creation bytecode.
     */
    function getCode(string calldata contractPath) external returns (bytes memory code);

    /**
     * @notice Gets the nonce of an account.
     * @param account The address of the account.
     * @return nonce The current nonce of the account.
     */
    function getNonce(address account) external returns (uint64 nonce);

    /**
     * @notice Sets the nonce of an account.
     * @dev The new nonce must be strictly higher than the current nonce.
     * @param account The address of the account.
     * @param nonce The new nonce to set.
     */
    function setNonce(address account, uint64 nonce) external;

    /**
     * @notice Performs a foreign function interface (FFI) call via the terminal.
     * @dev Requires `fuzzing.chainConfig.cheatCodes.enableFFI` to be true in the config. Use with caution due to security risks.
     * @param command An array of strings representing the command and its arguments.
     * @return result The output of the command as bytes.
     */
    function ffi(string[] calldata command) external returns (bytes memory result);

    /**
     * @notice Takes a snapshot of the current EVM state.
     * @return snapshotId An identifier for the created snapshot.
     */
    function snapshot() external returns (uint256 snapshotId);

    /**
     * @notice Reverts the EVM state back to a previously taken snapshot.
     * @param snapshotId The identifier of the snapshot to revert to.
     * @return success True if the revert was successful, false otherwise.
     */
    function revertTo(uint256 snapshotId) external returns (bool success);

    /**
     * @notice Converts an address to its string representation.
     * @param value The address value.
     * @return str The string representation (e.g., "0x...").
     */
    function toString(address value) external returns (string memory str);

    /**
     * @notice Converts bytes to a hex-encoded string prefixed with "0x".
     * @param value The bytes value.
     * @return str The hex string representation.
     */
    function toString(bytes calldata value) external returns (string memory str);

    /**
     * @notice Converts bytes32 to a hex-encoded string prefixed with "0x".
     * @param value The bytes32 value.
     * @return str The hex string representation.
     */
    function toString(bytes32 value) external returns (string memory str);

    /**
     * @notice Converts a boolean to its string representation ("true" or "false").
     * @param value The boolean value.
     * @return str The string representation.
     */
    function toString(bool value) external returns (string memory str);

    /**
     * @notice Converts a uint256 to its decimal string representation.
     * @param value The uint256 value.
     * @return str The string representation.
     */
    function toString(uint256 value) external returns (string memory str);

    /**
     * @notice Converts an int256 to its decimal string representation.
     * @param value The int256 value.
     * @return str The string representation.
     */
    function toString(int256 value) external returns (string memory str);

    /**
     * @notice Parses a string into bytes.
     * @param s The string to parse.
     * @return value The resulting bytes value.
     */
    function parseBytes(string memory s) external returns (bytes memory value);

    /**
     * @notice Parses a string into bytes32.
     * @param s The string to parse.
     * @return value The resulting bytes32 value.
     */
    function parseBytes32(string memory s) external returns (bytes32 value);

    /**
     * @notice Parses a string into an address.
     * @param s The string to parse (e.g., "0x...").
     * @return value The resulting address value.
     */
    function parseAddress(string memory s) external returns (address value);

    /**
     * @notice Parses a string into a uint256.
     * @param s The decimal string to parse.
     * @return value The resulting uint256 value.
     */
    function parseUint(string memory s) external returns (uint256 value);

    /**
     * @notice Parses a string into an int256.
     * @param s The decimal string to parse.
     * @return value The resulting int256 value.
     */
    function parseInt(string memory s) external returns (int256 value);

    /**
     * @notice Parses a string ("true" or "false") into a boolean.
     * @param s The string to parse.
     * @return value The resulting boolean value.
     */
    function parseBool(string memory s) external returns (bool value);
}
