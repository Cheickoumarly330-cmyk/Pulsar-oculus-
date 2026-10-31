// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnTest {
    mapping(address => uint) public balances;

    function withdraw() public {
        uint bal = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok);
        balances[msg.sender] = 0;
    }

    function mint() public {
        _mint(msg.sender, 1000);
    }

    function _mint(address to, uint amount) internal {
        balances[to] += amount;
    }
}
