// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import { ERC20Storage, erc20Storage } from "./OFTStorage.sol";
import { LibERC20 } from "./LibERC20.sol";
import { LibOFTConstants as C } from "./LibOFTConstants.sol";

contract ERC20Facet {
    /**
     * @dev Get total supply of token.
     * @return total supply.
     */
    function totalSupply() external view returns (uint256) {
        return erc20Storage().totalSupply;
    }

    /**
     * @dev Get token balance of given wallet.
     * @param addr wallet whose balance to get.
     * @return balance of wallet.
     */
    function balanceOf(address addr) external view returns (uint256) {
        return erc20Storage().balances[addr];
    }

    function name() external pure returns (string memory) {
        return C.NAME;
    }

    function symbol() external pure returns (string memory) {
        return C.SYMBOL;
    }

    function decimals() external pure returns (uint8) {
        return C.DECIMALS;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        LibERC20._approve(msg.sender, spender, amount, true);

        return true;
    }

    function allowance(address owner, address spender) external view returns (uint256) {
        return erc20Storage().allowance[owner][spender];
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        LibERC20._transfer(msg.sender, to, amount);

        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        LibERC20._spendAllowance(from, msg.sender, amount);
        LibERC20._transfer(from, to, amount);

        return true;
    }
}
