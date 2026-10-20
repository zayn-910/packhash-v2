// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract PacketRegistry {
    struct Anchor {
        bytes32 sessionRoot;   // Merkle root of this session's packets
        bytes32 chainRoot;     // sha256(previous chainRoot + sessionRoot)
        uint256 packetCount;
        uint256 timestamp;
    }

    address public owner;
    Anchor[] private anchors;  // append-only: nothing is ever edited or removed

    event Sealed(
        uint256 indexed id,
        bytes32 sessionRoot,
        bytes32 chainRoot,
        uint256 packetCount,
        uint256 timestamp
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can seal");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function seal(bytes32 sessionRoot, uint256 packetCount)
        external
        onlyOwner
        returns (uint256 id)
    {
        require(packetCount > 0, "Empty session");

        bytes32 prev = anchors.length == 0
            ? bytes32(0)
            : anchors[anchors.length - 1].chainRoot;
        bytes32 chainRoot = sha256(abi.encodePacked(prev, sessionRoot));

        anchors.push(Anchor(sessionRoot, chainRoot, packetCount, block.timestamp));
        id = anchors.length - 1;

        emit Sealed(id, sessionRoot, chainRoot, packetCount, block.timestamp);
    }

    function anchorCount() external view returns (uint256) {
        return anchors.length;
    }

    function getAnchor(uint256 id)
        external
        view
        returns (
            bytes32 sessionRoot,
            bytes32 chainRoot,
            uint256 packetCount,
            uint256 timestamp
        )
    {
        require(id < anchors.length, "No such anchor");
        Anchor storage a = anchors[id];
        return (a.sessionRoot, a.chainRoot, a.packetCount, a.timestamp);
    }
}
