pragma solidity  ^0.4.25;

contract Ownable {
  constructor() internal {
    owner = msg.sender;
  }

  address owner;

  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  event OwnerSet(address);

  function setOwner(address _owner)
  public onlyOwner
  {
    owner = _owner;
    emit OwnerSet(_owner);
  }
}
