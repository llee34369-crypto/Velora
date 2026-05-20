export interface ContractTemplate {
  name: string;
  description: string;
  code: string;
}

export const CONTRACT_TEMPLATES: ContractTemplate[] = [
  {
    name: "Vulnerable Reentrancy Vault",
    description: "A classic bank contract that is susceptible to reentrancy attacks because of the 'Checks-Effects-Interactions' pattern violation.",
    code: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract EtherStore {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: The balance is updated AFTER sending the ether.
    // An attacker can recursively call withdraw() inside their receive() fallback function!
    function withdraw() public {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "Zero balance");

        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "Failed to send Ether");

        balances[msg.sender] = 0; // State change happens after interaction!
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}`
  },
  {
    name: "Unprotected Flash Loan Target",
    description: "An AMM or swap receiver lacking slippage boundaries, allowing arbitrage and price manipulation via flash loans.",
    code: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IUniswapV2Pair {
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
}

contract PriceReceiver {
    address public poolAddress;
    address public oracleAddress;
    
    // VULNERABLE: Relies on instantaneous AMM reserves to calculate asset valuation 
    // instead of a time-weighted average price (TWAP) or secure oracle.
    function getAssetPrice(address token) public view returns (uint256) {
        uint256 reserve0 = IERC20(poolAddress).balanceOf(poolAddress);
        uint256 reserve1 = IERC20(oracleAddress).balanceOf(poolAddress);
        return reserve1 / reserve0; // Spot price: easily manipulated in a single tx!
    }

    function executeForceLiquidate(address user) public {
        uint256 currentPrice = getAssetPrice(address(0));
        require(currentPrice < 100, "User is safe");
        // Perform liquidation actions...
    }
}`
  },
  {
    name: "Proxy Delegatecall Hijack",
    description: "A proxy structure pattern that allows arbitrary memory location manipulation via delegatecalls containing unvalidated parameters.",
    code: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Proxy {
    address public implementation;
    address public owner;

    constructor(address _impl) {
        implementation = _impl;
        owner = msg.sender;
    }

    // VULNERABLE: Allows any external caller to trigger standard delegatecalls 
    // and write to the implementation storage slots blindly.
    fallback() external payable {
        address impl = implementation;
        require(impl != address(0));

        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, 0, calldatasize())
            let result := delegatecall(gas(), impl, ptr, calldatasize(), 0, 0)
            let size := returndatasize()
            returndatacopy(ptr, 0, size)
            switch result
            case 0 { revert(ptr, size) }
            default { return(ptr, size) }
        }
    }
}`
  },
  {
    name: "Insecure tx.origin Authorization",
    description: "A wallet or vault relying on tx.origin instead of msg.sender, enabling malicious phishing contracts to drain core treasury.",
    code: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TxOriginWallet {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {}

    // VULNERABLE: tx.origin is the original initiator who sent the root transaction.
    // If the owner connects to a malicious contract which calls withdraw(), 
    // tx.origin matches the owner, and all funds are hijacked!
    function transferFunds(address payable _to, uint256 _amount) public {
        require(tx.origin == owner, "Not authorized");
        
        (bool success, ) = _to.call{value: _amount}("");
        require(success, "Transfer failed");
    }
}`
  }
];
