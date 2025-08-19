// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {HookMiner} from "@uniswap/v4-periphery/src/utils/HookMiner.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {console} from "forge-std/console.sol";

import {BaseScript} from "./base/BaseScript.sol";
import {TaxHook} from "../src/TaxHook.sol";

/// @notice Mines the address and deploys the TaxHook.sol contract
contract DeployTaxHookScript is BaseScript {
    // Configuration parameters for TaxHook deployment
    // Note: Update these values as needed for your deployment
    Currency constant HOUSE_TOKEN = Currency.wrap(0xa513E6E4b8f2a923D98304ec87F64353C4D5C853); // Example HOUSE token address
    address constant TREASURY = 0x742d35cC6635c0532925A3b8cDb41FAD4bBE5B27; // Example treasury address
    uint256 constant SELL_TAX_BIPS = 500; // 5% sell tax
    uint256 constant BUY_TAX_BIPS = 300;  // 3% buy tax

    function run() public {
        // TaxHook requires beforeSwap and beforeSwapReturnDelta flags
        uint160 flags = uint160(
            Hooks.BEFORE_SWAP_FLAG | Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG
        );

        // Prepare constructor arguments for TaxHook
        bytes memory constructorArgs = abi.encode(
            poolManager,    // IPoolManager
            HOUSE_TOKEN,    // Currency _houseToken
            TREASURY,       // address _treasury
            SELL_TAX_BIPS, // uint256 _sellTaxBips
            BUY_TAX_BIPS,  // uint256 _buyTaxBips
            deployerAddress // address _owner
        );

        // Mine a salt that will produce a hook address with the correct flags
        (address hookAddress, bytes32 salt) =
            HookMiner.find(CREATE2_FACTORY, flags, type(TaxHook).creationCode, constructorArgs);

        // Deploy the hook using CREATE2
        vm.startBroadcast();
        TaxHook taxHook = new TaxHook{salt: salt}(
            poolManager,
            HOUSE_TOKEN,
            TREASURY,
            SELL_TAX_BIPS,
            BUY_TAX_BIPS,
            deployerAddress
        );
        vm.stopBroadcast();

        require(address(taxHook) == hookAddress, "DeployTaxHookScript: Hook Address Mismatch");

        // Log deployment details
        console.log("TaxHook deployed at:", address(taxHook));
        console.log("House Token:", Currency.unwrap(HOUSE_TOKEN));
        console.log("Treasury:", TREASURY);
        console.log("Sell Tax (bips):", SELL_TAX_BIPS);
        console.log("Buy Tax (bips):", BUY_TAX_BIPS);
        console.log("Owner:", deployerAddress);
    }
} 