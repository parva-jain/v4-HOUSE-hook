// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {BaseHook} from "@openzeppelin/uniswap-hooks/src/base/BaseHook.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {IPoolManager, SwapParams} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary, toBeforeSwapDelta} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";
import {Currency, CurrencyLibrary} from "@uniswap/v4-core/src/types/Currency.sol";
import {SafeCast} from "@uniswap/v4-core/src/libraries/SafeCast.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract TaxHook is BaseHook, Ownable {
    using PoolIdLibrary for PoolKey;
    using SafeCast for uint256;
    using CurrencyLibrary for Currency;

    // -----------------------------------------------
    // CONSTANTS AND STATE VARIABLES
    // -----------------------------------------------

    uint256 public constant MAX_TAX_BIPS = 2000; // Maximum 20% tax
    uint256 public constant BIPS_DENOMINATOR = 10000;

    Currency public immutable HOUSE_TOKEN;
    address public treasury;

    uint256 public sellTaxBips; // Tax when selling HOUSE (HOUSE → other)
    uint256 public buyTaxBips;  // Tax when buying HOUSE (other → HOUSE)

    uint256 public totalTaxesCollected;

    // Per-currency tax tracking (token address => total amount collected)
    mapping(address => uint256) public currencyTaxesCollected;

    // -----------------------------------------------
    // EVENTS
    // -----------------------------------------------

    event TaxCollected(
        PoolId indexed poolId,
        address indexed user,
        bool isBuy,
        uint256 taxAmount,
        uint256 swapAmount,
        address indexed currency
    );

    event TaxRatesUpdated(uint256 newSellTax, uint256 newBuyTax);
    event TreasuryUpdated(address indexed oldTreasury, address indexed newTreasury);

    // -----------------------------------------------
    // ERRORS
    // -----------------------------------------------

    error InvalidTaxRate();
    error InvalidTreasury();
    error NotHousePool();

    // -----------------------------------------------
    // CONSTRUCTOR
    // -----------------------------------------------

    constructor(
        IPoolManager _poolManager,
        Currency _houseToken,
        address _treasury,
        uint256 _sellTaxBips,
        uint256 _buyTaxBips,
        address _owner
    ) BaseHook(_poolManager) Ownable(_owner) {
        if (_treasury == address(0)) revert InvalidTreasury();
        if (_sellTaxBips > MAX_TAX_BIPS || _buyTaxBips > MAX_TAX_BIPS) revert InvalidTaxRate();

        HOUSE_TOKEN = _houseToken;
        treasury = _treasury;
        sellTaxBips = _sellTaxBips;
        buyTaxBips = _buyTaxBips;

        emit TaxRatesUpdated(_sellTaxBips, _buyTaxBips);
        emit TreasuryUpdated(address(0), _treasury);
    }

    // -----------------------------------------------
    // HOOK PERMISSIONS
    // -----------------------------------------------

    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: false,
            beforeAddLiquidity: false,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: true,  // For tax collection using BeforeSwapDelta
            afterSwap: false,  
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: true,  // Enable BeforeSwapDelta return
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    // -----------------------------------------------
    // HOOK FUNCTIONS
    // -----------------------------------------------

    function _beforeSwap(
        address sender,
        PoolKey calldata key,
        SwapParams calldata params,
        bytes calldata
    ) internal override returns (bytes4, BeforeSwapDelta, uint24) {
        // Validate that this pool involves HOUSE token
        if (!_isHousePool(key)) revert NotHousePool();
        
        // Calculate swap amount (always positive)
        uint256 swapAmount = params.amountSpecified < 0 
            ? uint256(-params.amountSpecified) 
            : uint256(params.amountSpecified);
            
        // Determine if this is a buy or sell operation
        bool isBuy = _isBuyOperation(key, params);
        
        // Calculate tax amount
        uint256 taxRate = isBuy ? buyTaxBips : sellTaxBips;
        uint256 taxAmount = (swapAmount * taxRate) / BIPS_DENOMINATOR;
        
        if (taxAmount > 0) {
            // Determine which currency to take the tax from
            Currency taxCurrency;
            if (isBuy) {
                // For buy operations: take tax from the input currency (what user is paying)
                bool specifiedTokenIs0 = (params.amountSpecified < 0 == params.zeroForOne);
                taxCurrency = specifiedTokenIs0 ? key.currency0 : key.currency1;
            } else {
                // For sell operations: take tax from HOUSE (what user is selling)
                taxCurrency = HOUSE_TOKEN;
            }
            
            // Take the tax from the pool (creates debt for hook)
            poolManager.take(taxCurrency, address(this), taxAmount);
            
            // Immediately transfer the collected tax to treasury
            taxCurrency.transfer(treasury, taxAmount);
            
            // Update accounting by currency
            address currencyAddress = Currency.unwrap(taxCurrency);
            totalTaxesCollected += taxAmount;
            currencyTaxesCollected[currencyAddress] += taxAmount;
            
            emit TaxCollected(key.toId(), sender, isBuy, taxAmount, swapAmount, currencyAddress);
            
            // Create BeforeSwapDelta to transfer the tax debt to the swap router
            // The user will end up paying the tax as part of their swap
            BeforeSwapDelta returnDelta = toBeforeSwapDelta(
                int128(int256(taxAmount)), // Specified delta (tax amount)
                0 // Unspecified delta (no change to other currency)
            );
            
            return (BaseHook.beforeSwap.selector, returnDelta, 0);
        }
        
        return (BaseHook.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
    }

    // -----------------------------------------------
    // INTERNAL FUNCTIONS
    // -----------------------------------------------

    function _isHousePool(PoolKey calldata key) internal view returns (bool) {
        return key.currency0 == HOUSE_TOKEN || key.currency1 == HOUSE_TOKEN;
    }
    
    function _isBuyOperation(PoolKey calldata key, SwapParams calldata params) internal view returns (bool) {
        // Determine which currency is specified (the input) and which is unspecified (the output)
        bool specifiedTokenIs0 = (params.amountSpecified < 0 == params.zeroForOne);
        
        // If HOUSE is the unspecified currency (output), user is buying HOUSE
        // If HOUSE is the specified currency (input), user is selling HOUSE
        if (specifiedTokenIs0) {
            // currency0 is input, currency1 is output
            return key.currency1 == HOUSE_TOKEN; // HOUSE is output = buy
        } else {
            // currency1 is input, currency0 is output  
            return key.currency0 == HOUSE_TOKEN; // HOUSE is output = buy
        }
    }

    // -----------------------------------------------
    // ADMIN FUNCTIONS
    // -----------------------------------------------

    function updateTaxRates(uint256 _sellTaxBips, uint256 _buyTaxBips) external onlyOwner {
        if (_sellTaxBips > MAX_TAX_BIPS || _buyTaxBips > MAX_TAX_BIPS) revert InvalidTaxRate();
        
        sellTaxBips = _sellTaxBips;
        buyTaxBips = _buyTaxBips;

        emit TaxRatesUpdated(_sellTaxBips, _buyTaxBips);
    }

    function updateTreasury(address _newTreasury) external onlyOwner {
        if (_newTreasury == address(0)) revert InvalidTreasury();
        
        address oldTreasury = treasury;
        treasury = _newTreasury;

        emit TreasuryUpdated(oldTreasury, _newTreasury);
    }

    // -----------------------------------------------
    // VIEW FUNCTIONS
    // -----------------------------------------------

    function getCurrencyTaxes(address currencyAddress) external view returns (uint256) {
        return currencyTaxesCollected[currencyAddress];
    }

    function calculateTax(uint256 amount, bool isBuy) external view returns (uint256) {
        uint256 taxRate = isBuy ? buyTaxBips : sellTaxBips;
        return (amount * taxRate) / BIPS_DENOMINATOR;
    }
}