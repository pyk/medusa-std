// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {FuzzVM} from "./FuzzVM.sol";

/**
 * @title FuzzTest
 * @author pyk
 * @notice Provides helper functions and utilities for writing Medusa fuzz tests, inspired by forge-std.
 * @dev Inherit from this contract to access Medusa cheatcodes and helpers easily.
 */
abstract contract FuzzTest {
    /**
     * @notice The address where Medusa cheatcodes are accessible.
     */
    address internal constant VM_ADDRESS = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D;

    /**
     * @notice An instance of the Medusa FuzzVM interface for accessing cheatcodes.
     */
    FuzzVM internal constant fvm = FuzzVM(VM_ADDRESS);

    /**
     * @notice Default ETH balance assigned when using hoax functions without specifying a balance.
     * Set to a high value to avoid insufficient balance issues during tests.
     */
    uint256 internal constant DEFAULT_BALANCE = 2 ** 128;

    ////////////////////////////////////////////////////////////////
    //                  msg.sender Manipulation                   //
    ////////////////////////////////////////////////////////////////

    /**
     * @notice Sets the `msg.sender` for the *next* call only.
     * @param who The address to prank as.
     * @dev Wraps `fvm.prank(address)`.
     */
    function prank(address who) internal virtual {
        fvm.prank(who);
    }

    /**
     * @notice Sets `msg.sender` for all subsequent calls until `stopPrank` is called.
     * @param who The address to start the prank as.
     * @dev Wraps `fvm.startPrank(address)`.
     */
    function startPrank(address who) internal virtual {
        fvm.startPrank(who);
    }

    /**
     * @notice Stops an active prank started by `startPrank`, resetting `msg.sender`.
     * @dev Wraps `fvm.stopPrank()`.
     */
    function stopPrank() internal virtual {
        fvm.stopPrank();
    }

    /**
     * @notice Sets `msg.sender` to the input address until the current call context exits.
     * @param who The address to prank as for the current call stack depth.
     * @dev Wraps `fvm.prankHere(address)`.
     */
    function prankHere(address who) internal virtual {
        fvm.prankHere(who);
    }

    ////////////////////////////////////////////////////////////////
    //                     State Manipulation                     //
    ////////////////////////////////////////////////////////////////

    /**
     * @notice Sets an address's ETH balance.
     * @param who The address whose balance will be set.
     * @param newBalance The new balance in wei.
     * @dev Wraps `fvm.deal(address, uint256)`.
     */
    function deal(address who, uint256 newBalance) internal virtual {
        fvm.deal(who, newBalance);
    }

    /**
     * @notice Sets an address's bytecode.
     * @param who The address whose code will be set.
     * @param code The new bytecode to deploy at the address.
     * @dev Wraps `fvm.etch(address, bytes)`.
     */
    function etch(address who, bytes calldata code) internal virtual {
        fvm.etch(who, code);
    }

    /**
     * @notice Sets the `block.timestamp`.
     * @param newTimestamp The new timestamp value.
     * @dev Wraps `fvm.warp(uint256)`.
     */
    function warp(uint256 newTimestamp) internal virtual {
        fvm.warp(newTimestamp);
    }

    /**
     * @notice Sets the `block.number`.
     * @param newBlockNumber The new block number value.
     * @dev Wraps `fvm.roll(uint256)`.
     */
    function roll(uint256 newBlockNumber) internal virtual {
        fvm.roll(newBlockNumber);
    }

    /**
     * @notice Sets the `block.basefee`.
     * @param newBasefee The new basefee value.
     * @dev Wraps `fvm.fee(uint256)`.
     */
    function fee(uint256 newBasefee) internal virtual {
        fvm.fee(newBasefee);
    }

    /**
     * @notice Sets the `block.prevrandao`.
     * @param newPrevrandao The new prevrandao value.
     * @dev Wraps `fvm.prevrandao(bytes32)`.
     */
    function prevrandao(bytes32 newPrevrandao) internal virtual {
        fvm.prevrandao(newPrevrandao);
    }

    /**
     * @notice Sets the `block.chainid`.
     * @param newChainId The new chain ID value.
     * @dev Wraps `fvm.chainId(uint256)`.
     */
    function chainId(uint256 newChainId) internal virtual {
        fvm.chainId(newChainId);
    }

    /**
     * @notice Sets the `block.coinbase`.
     * @param newCoinbase The new coinbase address.
     * @dev Wraps `fvm.coinbase(address)`.
     */
    function coinbase(address newCoinbase) internal virtual {
        fvm.coinbase(newCoinbase);
    }

    /**
     * @notice Stores a value to an address' storage slot.
     * @param account The target account address.
     * @param slot The storage slot to modify.
     * @param value The value to store.
     * @dev Wraps `fvm.store(address, bytes32, bytes32)`.
     */
    function store(address account, bytes32 slot, bytes32 value) internal virtual {
        fvm.store(account, slot, value);
    }

    /**
     * @notice Loads a storage slot from an address.
     * @param account The target account address.
     * @param slot The storage slot to load.
     * @return value The value stored at the specified slot.
     * @dev Wraps `fvm.load(address, bytes32)`.
     */
    function load(address account, bytes32 slot) internal virtual returns (bytes32 value) {
        return fvm.load(account, slot);
    }

    ////////////////////////////////////////////////////////////////
    //                      Nonce Management                      //
    ////////////////////////////////////////////////////////////////

    /**
     * @notice Gets the nonce of an account.
     * @param account The address of the account.
     * @return nonce The current nonce of the account.
     * @dev Wraps `fvm.getNonce(address)`.
     */
    function getNonce(address account) internal virtual returns (uint64 nonce) {
        return fvm.getNonce(account);
    }

    /**
     * @notice Sets the nonce of an account.
     * @dev The new nonce must be strictly higher than the current nonce.
     * @param account The address of the account.
     * @param newNonce The new nonce to set.
     * @dev Wraps `fvm.setNonce(address, uint64)`.
     */
    function setNonce(address account, uint64 newNonce) internal virtual {
        fvm.setNonce(account, newNonce);
    }

    ////////////////////////////////////////////////////////////////
    //                      Address helpers                       //
    ////////////////////////////////////////////////////////////////

    /**
     * @notice Computes the Ethereum address associated with a given private key.
     * @param privateKey The private key.
     * @return addr The computed address.
     * @dev Wraps `fvm.addr(uint256)`.
     */
    function addr(uint256 privateKey) internal virtual returns (address addr) {
        return fvm.addr(privateKey);
    }

    /**
     * @notice Signs a digest using a private key.
     * @param privateKey The private key to sign with.
     * @param digest The 32-byte hash digest to sign.
     * @return v The recovery ID.
     * @return r The R value of the signature.
     * @return s The S value of the signature.
     * @dev Wraps `fvm.sign(uint256, bytes32)`.
     */
    function sign(uint256 privateKey, bytes32 digest) internal virtual returns (uint8 v, bytes32 r, bytes32 s) {
        return fvm.sign(privateKey, digest);
    }

    ////////////////////////////////////////////////////////////////
    //                        String stuff                        //
    ////////////////////////////////////////////////////////////////

    // Note: These just re-expose the VM functions for convenience within the Test contract context.

    function toString(address value) internal virtual returns (string memory str) {
        return fvm.toString(value);
    }

    function toString(bytes calldata value) internal virtual returns (string memory str) {
        return fvm.toString(value);
    }

    function toString(bytes32 value) internal virtual returns (string memory str) {
        return fvm.toString(value);
    }

    function toString(bool value) internal virtual returns (string memory str) {
        return fvm.toString(value);
    }

    function toString(uint256 value) internal virtual returns (string memory str) {
        return fvm.toString(value);
    }

    function toString(int256 value) internal virtual returns (string memory str) {
        return fvm.toString(value);
    }

    function parseBytes(string memory s) internal virtual returns (bytes memory value) {
        return fvm.parseBytes(s);
    }

    function parseBytes32(string memory s) internal virtual returns (bytes32 value) {
        return fvm.parseBytes32(s);
    }

    function parseAddress(string memory s) internal virtual returns (address value) {
        return fvm.parseAddress(s);
    }

    function parseUint(string memory s) internal virtual returns (uint256 value) {
        return fvm.parseUint(s);
    }

    function parseInt(string memory s) internal virtual returns (int256 value) {
        return fvm.parseInt(s);
    }

    function parseBool(string memory s) internal virtual returns (bool value) {
        return fvm.parseBool(s);
    }

    ////////////////////////////////////////////////////////////////
    //                         Snapshots                          //
    ////////////////////////////////////////////////////////////////

    /**
     * @notice Takes a snapshot of the current EVM state.
     * @return snapshotId An identifier for the created snapshot.
     * @dev Wraps `fvm.snapshot()`.
     */
    function snapshot() internal virtual returns (uint256 snapshotId) {
        return fvm.snapshot();
    }

    /**
     * @notice Reverts the EVM state back to a previously taken snapshot.
     * @param snapshotId The identifier of the snapshot to revert to.
     * @return success True if the revert was successful, false otherwise.
     * @dev Wraps `fvm.revertTo(uint256)`.
     */
    function revertTo(uint256 snapshotId) internal virtual returns (bool success) {
        return fvm.revertTo(snapshotId);
    }

    ////////////////////////////////////////////////////////////////
    //                            FFI                             //
    ////////////////////////////////////////////////////////////////

    /**
     * @notice Performs a foreign function interface (FFI) call via the terminal.
     * @param command An array of strings representing the command and its arguments.
     * @return result The output of the command as bytes.
     * @dev Wraps `fvm.ffi(string[])`. Requires FFI enabled in Medusa config. Use with caution.
     */
    function ffi(string[] calldata command) internal virtual returns (bytes memory result) {
        return fvm.ffi(command);
    }

    ////////////////////////////////////////////////////////////////
    //                 forge-std Style Utilities                  //
    ////////////////////////////////////////////////////////////////

    /**
     * @notice Creates a labeled address and the corresponding private key deterministically from a string name.
     * @param name The string label used to derive the private key.
     * @return addr The derived address.
     * @return privateKey The derived private key.
     * @dev Uses keccak256 on the name to generate the private key, then `fvm.addr` to get the address.
     */
    function makeAddrAndKey(string memory name) internal virtual returns (address addr, uint256 privateKey) {
        privateKey = uint256(keccak256(abi.encodePacked(name)));
        addr = fvm.addr(privateKey);
        // Medusa does not support labeling directly via cheatcode
    }

    /**
     * @notice Creates a labeled address deterministically from a string name.
     * @param name The string label used to derive the private key and address.
     * @return addr The derived address.
     * @dev Uses `makeAddrAndKey` internally.
     */
    function makeAddr(string memory name) internal virtual returns (address addr) {
        (addr,) = makeAddrAndKey(name);
    }

    /**
     * @notice Sets the balance for `who` and pranks as `who` for the next call.
     * @param who The address to set balance for and prank as.
     * @param give The amount of ETH (in wei) to give.
     * @dev Combines `deal` and `prank`.
     */
    function hoax(address who, uint256 give) internal virtual {
        deal(who, give);
        prank(who);
    }

    /**
     * @notice Sets the balance for `who` to `DEFAULT_BALANCE` and pranks as `who` for the next call.
     * @param who The address to set balance for and prank as.
     * @dev Combines `deal` and `prank` using `DEFAULT_BALANCE`.
     */
    function hoax(address who) internal virtual {
        hoax(who, DEFAULT_BALANCE);
    }

    /**
     * @notice Sets the balance for `who` and starts a prank as `who` for subsequent calls.
     * @param who The address to set balance for and start pranking as.
     * @param give The amount of ETH (in wei) to give.
     * @dev Combines `deal` and `startPrank`.
     */
    function startHoax(address who, uint256 give) internal virtual {
        deal(who, give);
        startPrank(who);
    }

    /**
     * @notice Sets the balance for `who` to `DEFAULT_BALANCE` and starts a prank as `who` for subsequent calls.
     * @param who The address to set balance for and start pranking as.
     * @dev Combines `deal` and `startPrank` using `DEFAULT_BALANCE`.
     */
    function startHoax(address who) internal virtual {
        startHoax(who, DEFAULT_BALANCE);
    }

    /**
     * @notice Skips forward `block.timestamp` by the specified number of seconds.
     * @param time The number of seconds to add to the current block timestamp.
     * @dev This is an alias for `fvm.warp(block.timestamp + time)`.
     */
    function skip(uint256 time) internal virtual {
        fvm.warp(block.timestamp + time);
    }

    /**
     * @notice Bounds a number to a specific range [min, max].
     * @param x The number to bound.
     * @param min The minimum value (inclusive).
     * @param max The maximum value (inclusive).
     * @return result The bounded number.
     * @dev If x is outside the range, it wraps around using the modulo operator.
     */
    function bound(uint256 x, uint256 min, uint256 max) internal pure virtual returns (uint256 result) {
        // Ensure min <= max to avoid division by zero or unexpected behavior
        if (min > max) {
            (min, max) = (max, min);
        }
        // Calculate the range size, add 1 because the range is inclusive
        uint256 rangeSize = max - min + 1;
        // Calculate the bounded value
        result = min + (x % rangeSize);
        return result;
    }

    ////////////////////////////////////////////////////////////////
    //                    Standard Assertions                     //
    ////////////////////////////////////////////////////////////////

    // These are standard Solidity functions, not cheatcode wrappers,
    // included for compatibility with forge-std testing style.

    /**
     * @notice Asserts that `condition` is true. Reverts otherwise.
     */
    function assertTrue(bool condition) internal virtual {
        assertTrue(condition, "Assertion failed: Expected true, got false");
    }

    /**
     * @notice Asserts that `condition` is true. Reverts with a message `err` otherwise.
     */
    function assertTrue(bool condition, string memory err) internal virtual {
        if (!condition) {
            revert(err);
        }
    }

    /**
     * @notice Asserts that `condition` is false. Reverts otherwise.
     */
    function assertFalse(bool condition) internal virtual {
        assertFalse(condition, "Assertion failed: Expected false, got true");
    }

    /**
     * @notice Asserts that `condition` is false. Reverts with a message `err` otherwise.
     */
    function assertFalse(bool condition, string memory err) internal virtual {
        if (condition) {
            revert(err);
        }
    }

    ////////////////////////////////////////////////////////////////
    //                                          //
    ////////////////////////////////////////////////////////////////

    // (Includes uint256, int256, address, bytes32, string, bytes)

    function assertEq(uint256 a, uint256 b) internal virtual {
        assertEq(a, b, "Assertion failed: uint256 inputs are not equal.");
    }

    function assertEq(uint256 a, uint256 b, string memory err) internal virtual {
        if (a != b) revert(err);
    }

    function assertEq(int256 a, int256 b) internal virtual {
        assertEq(a, b, "Assertion failed: int256 inputs are not equal.");
    }

    function assertEq(int256 a, int256 b, string memory err) internal virtual {
        if (a != b) revert(err);
    }

    function assertEq(address a, address b) internal virtual {
        assertEq(a, b, "Assertion failed: address inputs are not equal.");
    }

    function assertEq(address a, address b, string memory err) internal virtual {
        if (a != b) revert(err);
    }

    function assertEq(bytes32 a, bytes32 b) internal virtual {
        assertEq(a, b, "Assertion failed: bytes32 inputs are not equal.");
    }

    function assertEq(bytes32 a, bytes32 b, string memory err) internal virtual {
        if (a != b) revert(err);
    }

    function assertEq(string memory a, string memory b) internal virtual {
        assertEq(a, b, "Assertion failed: string inputs are not equal.");
    }

    function assertEq(string memory a, string memory b, string memory err) internal virtual {
        if (keccak256(abi.encodePacked(a)) != keccak256(abi.encodePacked(b))) revert(err);
    }

    function assertEq(bytes memory a, bytes memory b) internal virtual {
        assertEq(a, b, "Assertion failed: bytes inputs are not equal.");
    }

    function assertEq(bytes memory a, bytes memory b, string memory err) internal virtual {
        if (keccak256(a) != keccak256(b)) revert(err);
    }

    ////////////////////////////////////////////////////////////////
    //                   Comparison Assertions                    //
    ////////////////////////////////////////////////////////////////

    // (Includes uint256, int256)

    function assertGt(uint256 a, uint256 b) internal virtual {
        assertGt(a, b, "Assertion failed: uint256 input 'a' not strictly greater than 'b'.");
    }

    function assertGt(uint256 a, uint256 b, string memory err) internal virtual {
        if (a <= b) revert(err);
    }

    function assertGt(int256 a, int256 b) internal virtual {
        assertGt(a, b, "Assertion failed: int256 input 'a' not strictly greater than 'b'.");
    }

    function assertGt(int256 a, int256 b, string memory err) internal virtual {
        if (a <= b) revert(err);
    }

    function assertLt(uint256 a, uint256 b) internal virtual {
        assertLt(a, b, "Assertion failed: uint256 input 'a' not strictly less than 'b'.");
    }

    function assertLt(uint256 a, uint256 b, string memory err) internal virtual {
        if (a >= b) revert(err);
    }

    function assertLt(int256 a, int256 b) internal virtual {
        assertLt(a, b, "Assertion failed: int256 input 'a' not strictly less than 'b'.");
    }

    function assertLt(int256 a, int256 b, string memory err) internal virtual {
        if (a >= b) revert(err);
    }

    function assertGe(uint256 a, uint256 b) internal virtual {
        assertGe(a, b, "Assertion failed: uint256 input 'a' not greater than or equal to 'b'.");
    }

    function assertGe(uint256 a, uint256 b, string memory err) internal virtual {
        if (a < b) revert(err);
    }

    function assertGe(int256 a, int256 b) internal virtual {
        assertGe(a, b, "Assertion failed: int256 input 'a' not greater than or equal to 'b'.");
    }

    function assertGe(int256 a, int256 b, string memory err) internal virtual {
        if (a < b) revert(err);
    }

    function assertLe(uint256 a, uint256 b) internal virtual {
        assertLe(a, b, "Assertion failed: uint256 input 'a' not less than or equal to 'b'.");
    }

    function assertLe(uint256 a, uint256 b, string memory err) internal virtual {
        if (a > b) revert(err);
    }

    function assertLe(int256 a, int256 b) internal virtual {
        assertLe(a, b, "Assertion failed: int256 input 'a' not less than or equal to 'b'.");
    }

    function assertLe(int256 a, int256 b, string memory err) internal virtual {
        if (a > b) revert(err);
    }
}
