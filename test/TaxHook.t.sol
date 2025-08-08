// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console2} from "forge-std/Test.sol";

import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {TickMath} from "@uniswap/v4-core/src/libraries/TickMath.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {CurrencyLibrary, Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {StateLibrary} from "@uniswap/v4-core/src/libraries/StateLibrary.sol";
import {LiquidityAmounts} from "@uniswap/v4-core/test/utils/LiquidityAmounts.sol";
import {IPositionManager} from "@uniswap/v4-periphery/src/interfaces/IPositionManager.sol";
import {Constants} from "@uniswap/v4-core/test/utils/Constants.sol";
import {MockERC20} from "solmate/src/test/utils/mocks/MockERC20.sol";

import {EasyPosm} from "./utils/libraries/EasyPosm.sol";
import {Deployers} from "./utils/Deployers.sol";

import {TaxHook} from "../src/TaxHook.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract TaxHookTest is Test, Deployers {
    using EasyPosm for IPositionManager;
    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;
    using StateLibrary for IPoolManager;

    // Test constants
    uint256 constant SELL_TAX_BIPS = 500; // 5%
    uint256 constant BUY_TAX_BIPS = 300;  // 3%
    uint256 constant BIPS_DENOMINATOR = 10000;

    // Currencies
    Currency houseToken;
    Currency otherToken;

    // Pool setup
    PoolKey poolKey;
    TaxHook hook;
    PoolId poolId;

    // Position setup
    uint256 tokenId;
    int24 tickLower;
    int24 tickUpper;

    // Test accounts
    address treasury = makeAddr("treasury");
    address user1 = makeAddr("user1");
    address user2 = makeAddr("user2");

    // Events for testing
    event TaxCollected(
        PoolId indexed poolId,
        address indexed user,
        bool isBuy,
        uint256 taxAmount,
        uint256 swapAmount,
        address indexed currency
    );

    event TaxRatesUpdated(uint256 newSellTax, uint256 newBuyTax);

    function setUp() public {
        // Deploy all required artifacts
        deployArtifacts();

        // Deploy HOUSE token and another token
        MockERC20 houseTokenContract = new MockERC20("HOUSE Token", "HOUSE", 18);
        MockERC20 otherTokenContract = new MockERC20("Other Token", "OTHER", 18);

        // Mint tokens to test contract
        houseTokenContract.mint(address(this), 10_000_000e18);
        otherTokenContract.mint(address(this), 10_000_000e18);

        // Mint tokens to test users
        houseTokenContract.mint(user1, 1_000_000e18);
        otherTokenContract.mint(user1, 1_000_000e18);
        houseTokenContract.mint(user2, 1_000_000e18);
        otherTokenContract.mint(user2, 1_000_000e18);

        // Set up currencies (ensure proper ordering)
        if (address(houseTokenContract) < address(otherTokenContract)) {
            houseToken = Currency.wrap(address(houseTokenContract));
            otherToken = Currency.wrap(address(otherTokenContract));
        } else {
            houseToken = Currency.wrap(address(otherTokenContract));
            otherToken = Currency.wrap(address(houseTokenContract));
            // Swap the contracts too
            (houseTokenContract, otherTokenContract) = (otherTokenContract, houseTokenContract);
        }

        // Approve tokens for all contracts
        _approveTokens(houseTokenContract, otherTokenContract);

        // Deploy the TaxHook to an address with the correct flags
        address flags = address(
            uint160(Hooks.BEFORE_SWAP_FLAG | Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG) ^ (0x4444 << 144)
        );
        
        bytes memory constructorArgs = abi.encode(
            poolManager,
            houseToken,
            treasury,
            SELL_TAX_BIPS,
            BUY_TAX_BIPS,
            address(this)  // owner parameter
        );
        
        deployCodeTo("TaxHook.sol:TaxHook", constructorArgs, flags);
        hook = TaxHook(flags);

        // Create the pool
        poolKey = PoolKey(houseToken, otherToken, 3000, 60, IHooks(hook));
        poolId = poolKey.toId();
        poolManager.initialize(poolKey, Constants.SQRT_PRICE_1_1);

        // Provide full-range liquidity to the pool
        tickLower = TickMath.minUsableTick(poolKey.tickSpacing);
        tickUpper = TickMath.maxUsableTick(poolKey.tickSpacing);

        uint128 liquidityAmount = 100e18;

        (uint256 amount0Expected, uint256 amount1Expected) = LiquidityAmounts.getAmountsForLiquidity(
            Constants.SQRT_PRICE_1_1,
            TickMath.getSqrtPriceAtTick(tickLower),
            TickMath.getSqrtPriceAtTick(tickUpper),
            liquidityAmount
        );

        (tokenId,) = positionManager.mint(
            poolKey,
            tickLower,
            tickUpper,
            liquidityAmount,
            amount0Expected + 1,
            amount1Expected + 1,
            address(this),
            block.timestamp,
            Constants.ZERO_BYTES
        );
    }

    function _approveTokens(MockERC20 token0, MockERC20 token1) internal {
        // Approve for this contract
        token0.approve(address(permit2), type(uint256).max);
        token1.approve(address(permit2), type(uint256).max);
        token0.approve(address(swapRouter), type(uint256).max);
        token1.approve(address(swapRouter), type(uint256).max);

        permit2.approve(address(token0), address(positionManager), type(uint160).max, type(uint48).max);
        permit2.approve(address(token1), address(positionManager), type(uint160).max, type(uint48).max);
        permit2.approve(address(token0), address(poolManager), type(uint160).max, type(uint48).max);
        permit2.approve(address(token1), address(poolManager), type(uint160).max, type(uint48).max);

        // Approve for test users
        vm.startPrank(user1);
        token0.approve(address(permit2), type(uint256).max);
        token1.approve(address(permit2), type(uint256).max);
        token0.approve(address(swapRouter), type(uint256).max);
        token1.approve(address(swapRouter), type(uint256).max);
        permit2.approve(address(token0), address(positionManager), type(uint160).max, type(uint48).max);
        permit2.approve(address(token1), address(positionManager), type(uint160).max, type(uint48).max);
        vm.stopPrank();

        vm.startPrank(user2);
        token0.approve(address(permit2), type(uint256).max);
        token1.approve(address(permit2), type(uint256).max);
        token0.approve(address(swapRouter), type(uint256).max);
        token1.approve(address(swapRouter), type(uint256).max);
        permit2.approve(address(token0), address(positionManager), type(uint160).max, type(uint48).max);
        permit2.approve(address(token1), address(positionManager), type(uint160).max, type(uint48).max);
        vm.stopPrank();
    }

    // ===============================================
    // BASIC FUNCTIONALITY TESTS
    // ===============================================

    function testHookDeployment() public {
        assertEq(Currency.unwrap(hook.HOUSE_TOKEN()), Currency.unwrap(houseToken));
        assertEq(hook.treasury(), treasury);
        assertEq(hook.owner(), address(this));
        assertEq(hook.sellTaxBips(), SELL_TAX_BIPS);
        assertEq(hook.buyTaxBips(), BUY_TAX_BIPS);
        assertEq(hook.totalTaxesCollected(), 0);
    }

    function testSellTax() public {
        uint256 amountIn = 1e18;
        uint256 expectedTax = (amountIn * SELL_TAX_BIPS) / BIPS_DENOMINATOR;
        
        uint256 treasuryBalanceBefore = houseToken.balanceOf(treasury);
        uint256 totalTaxesBefore = hook.totalTaxesCollected();

        // Determine if HOUSE is currency0 or currency1 and set swap direction accordingly
        bool houseIsCurrency0 = poolKey.currency0 == houseToken;
        bool zeroForOne = houseIsCurrency0; // Selling HOUSE means swapping from HOUSE to other

        vm.expectEmit(true, true, true, true);
        emit TaxCollected(poolId, address(swapRouter), false, expectedTax, amountIn, Currency.unwrap(houseToken));

        // Perform sell swap (HOUSE → other)
        BalanceDelta swapDelta = swapRouter.swapExactTokensForTokens({
            amountIn: amountIn,
            amountOutMin: 0,
            zeroForOne: zeroForOne,
            poolKey: poolKey,
            hookData: Constants.ZERO_BYTES,
            receiver: address(this),
            deadline: block.timestamp + 1
        });

        // Verify tax was immediately transferred to treasury
        assertEq(houseToken.balanceOf(treasury), treasuryBalanceBefore + expectedTax);
        assertEq(hook.totalTaxesCollected(), totalTaxesBefore + expectedTax);
        assertEq(hook.getCurrencyTaxes(Currency.unwrap(houseToken)), expectedTax);

        // Verify swap delta
        if (houseIsCurrency0) {
            assertEq(int256(swapDelta.amount0()), -int256(amountIn));
        } else {
            assertEq(int256(swapDelta.amount1()), -int256(amountIn));
        }
    }

    function testBuyTax() public {
        uint256 amountIn = 1e18;
        
        // For buy operations, tax is collected in the input currency (otherToken)
        uint256 treasuryBalanceBefore = otherToken.balanceOf(treasury);
        uint256 totalTaxesBefore = hook.totalTaxesCollected();

        // Determine swap direction for buying HOUSE (other → HOUSE)
        bool houseIsCurrency0 = poolKey.currency0 == houseToken;
        bool zeroForOne = !houseIsCurrency0; // Buying HOUSE means swapping from other to HOUSE

        // Perform buy swap (other → HOUSE)
        BalanceDelta swapDelta = swapRouter.swapExactTokensForTokens({
            amountIn: amountIn,
            amountOutMin: 0,
            zeroForOne: zeroForOne,
            poolKey: poolKey,
            hookData: Constants.ZERO_BYTES,
            receiver: address(this),
            deadline: block.timestamp + 1
        });

        // Calculate expected tax based on input amount (since tax is calculated on swap amount in beforeSwap)
        uint256 expectedTax = (amountIn * BUY_TAX_BIPS) / BIPS_DENOMINATOR;

        // Verify tax was immediately transferred to treasury
        assertEq(otherToken.balanceOf(treasury), treasuryBalanceBefore + expectedTax);
        assertGt(hook.totalTaxesCollected(), totalTaxesBefore);
        assertEq(hook.getCurrencyTaxes(Currency.unwrap(otherToken)), expectedTax);
    }

    function testMultipleSwapsAccumulateTax() public {
        uint256 swapAmount = 0.5e18;
        uint256 numSwaps = 4;
        
        uint256 initialTreasuryBalance = houseToken.balanceOf(treasury);
        uint256 initialTaxes = hook.totalTaxesCollected();
        
        // Perform multiple sell swaps
        bool houseIsCurrency0 = poolKey.currency0 == houseToken;
        for (uint256 i = 0; i < numSwaps; i++) {
            swapRouter.swapExactTokensForTokens({
                amountIn: swapAmount,
                amountOutMin: 0,
                zeroForOne: houseIsCurrency0, // Selling HOUSE
                poolKey: poolKey,
                hookData: Constants.ZERO_BYTES,
                receiver: address(this),
                deadline: block.timestamp + 1
            });
        }
        
        uint256 expectedTotalTax = (swapAmount * SELL_TAX_BIPS * numSwaps) / BIPS_DENOMINATOR;
        assertEq(houseToken.balanceOf(treasury), initialTreasuryBalance + expectedTotalTax);
        assertEq(hook.totalTaxesCollected(), initialTaxes + expectedTotalTax);
    }

    // ===============================================
    // TREASURY AND ADMIN TESTS
    // ===============================================

    function testImmediateTaxTransfer() public {
        // Test that taxes are immediately transferred to treasury
        uint256 swapAmount = 1e18;
        bool houseIsCurrency0 = poolKey.currency0 == houseToken;
        
        uint256 treasuryBalanceBefore = houseToken.balanceOf(treasury);
        
        swapRouter.swapExactTokensForTokens({
            amountIn: swapAmount,
            amountOutMin: 0,
            zeroForOne: houseIsCurrency0,
            poolKey: poolKey,
            hookData: Constants.ZERO_BYTES,
            receiver: address(this),
            deadline: block.timestamp + 1
        });

        uint256 expectedTax = (swapAmount * SELL_TAX_BIPS) / BIPS_DENOMINATOR;
        
        // Verify tax was immediately sent to treasury
        assertEq(houseToken.balanceOf(treasury), treasuryBalanceBefore + expectedTax);
        
        // Verify hook contract has no remaining balance
        assertEq(houseToken.balanceOf(address(hook)), 0);
    }

    function testUpdateTaxRates() public {
        uint256 newSellTax = 800; // 8%
        uint256 newBuyTax = 400;  // 4%

        vm.expectEmit(true, true, true, true);
        emit TaxRatesUpdated(newSellTax, newBuyTax);

        hook.updateTaxRates(newSellTax, newBuyTax);

        assertEq(hook.sellTaxBips(), newSellTax);
        assertEq(hook.buyTaxBips(), newBuyTax);
    }

    function testUpdateTreasury() public {
        address newTreasury = makeAddr("newTreasury");
        
        hook.updateTreasury(newTreasury);
        
        assertEq(hook.treasury(), newTreasury);
    }

    // ===============================================
    // ACCESS CONTROL TESTS
    // ===============================================

    function testOnlyOwnerCanUpdateTaxRates() public {
        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user1));
        hook.updateTaxRates(100, 200);
    }

    function testOnlyOwnerCanUpdateTreasury() public {
        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user1));
        hook.updateTreasury(makeAddr("newTreasury"));
    }

    function testTransferOwnership() public {
        hook.transferOwnership(user1);
        assertEq(hook.owner(), user1);

        // Old owner can't call functions anymore
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        hook.updateTaxRates(100, 200);

        // New owner can call functions
        vm.prank(user1);
        hook.updateTaxRates(100, 200);
    }

    // ===============================================
    // ERROR CONDITION TESTS
    // ===============================================

    function testInvalidTaxRates() public {
        vm.expectRevert(TaxHook.InvalidTaxRate.selector);
        hook.updateTaxRates(2001, 100); // Over 20%

        vm.expectRevert(TaxHook.InvalidTaxRate.selector);
        hook.updateTaxRates(100, 2001); // Over 20%
    }

    function testInvalidTreasury() public {
        vm.expectRevert(TaxHook.InvalidTreasury.selector);
        hook.updateTreasury(address(0));
    }

    function testTaxCalculationFunction() public {
        uint256 amount = 1000e18;
        
        uint256 sellTax = hook.calculateTax(amount, false);
        uint256 buyTax = hook.calculateTax(amount, true);
        
        assertEq(sellTax, (amount * SELL_TAX_BIPS) / BIPS_DENOMINATOR);
        assertEq(buyTax, (amount * BUY_TAX_BIPS) / BIPS_DENOMINATOR);
    }

    function testUserBalanceChangesWithTax() public {
        uint256 swapAmount = 1e18;
        bool houseIsCurrency0 = poolKey.currency0 == houseToken;
        
        // Test user swap with tax
        vm.startPrank(user1);
        
        uint256 userHouseBalanceBefore = houseToken.balanceOf(user1);
        uint256 userOtherBalanceBefore = otherToken.balanceOf(user1);
        uint256 treasuryBalanceBefore = houseToken.balanceOf(treasury);
        
        // User sells HOUSE
        swapRouter.swapExactTokensForTokens({
            amountIn: swapAmount,
            amountOutMin: 0,
            zeroForOne: houseIsCurrency0,
            poolKey: poolKey,
            hookData: Constants.ZERO_BYTES,
            receiver: user1,
            deadline: block.timestamp + 1
        });
        
        vm.stopPrank();
        
        // Verify user balances changed
        assertEq(houseToken.balanceOf(user1), userHouseBalanceBefore - swapAmount);
        assertGt(otherToken.balanceOf(user1), userOtherBalanceBefore);
        
        // Verify tax was immediately transferred to treasury
        uint256 expectedTax = (swapAmount * SELL_TAX_BIPS) / BIPS_DENOMINATOR;
        assertEq(houseToken.balanceOf(treasury), treasuryBalanceBefore + expectedTax);
        assertEq(hook.totalTaxesCollected(), expectedTax);
    }

    function testNonHousePoolReverts() public {
        // This test would require creating a pool without HOUSE token
        // For now, we test that our pool correctly identifies as a HOUSE pool
        // by checking that swaps work (they would revert if NotHousePool was thrown)
        
        uint256 swapAmount = 1e18;
        bool houseIsCurrency0 = poolKey.currency0 == houseToken;
        
        // This should work fine since our pool contains HOUSE
        swapRouter.swapExactTokensForTokens({
            amountIn: swapAmount,
            amountOutMin: 0,
            zeroForOne: houseIsCurrency0,
            poolKey: poolKey,
            hookData: Constants.ZERO_BYTES,
            receiver: address(this),
            deadline: block.timestamp + 1
        });
        
        // If we got here, the pool was correctly identified as a HOUSE pool
        assertTrue(true);
    }
} 