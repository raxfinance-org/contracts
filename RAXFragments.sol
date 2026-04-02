// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title RAXFragments
/// @notice ERC-1155 Fragment NFT for the RAX Awakening Mystery Box activity.
///
///         Five fragment types (tokenId 1–5) are claimable by users who present an
///         admin-signed EIP-712 payload.  Each (claimId) may only be consumed once.
///
///         Fragments are non-transferable by regular users.  The Final NFT contract
///         (RAXAINode) is granted burn authority so it can atomically consume one of
///         each fragment type during Forge.
///
///         No proxy / upgradeability.  URIs are fixed at construction.
contract RAXFragments is ERC1155, Ownable, Pausable, EIP712 {
    using ECDSA for bytes32;

    // ─── Constants ────────────────────────────────────────────────────────────

    uint256 public constant FRAGMENT_COUNT = 5;

    /// @notice EIP-712 type hash for the Claim struct. Public for backend verification.
    bytes32 public constant CLAIM_TYPEHASH =
        keccak256("Claim(bytes32 claimId,uint256 tokenId,address recipient)");

    // ─── State ────────────────────────────────────────────────────────────────

    /// @notice Contract name — informational, for explorers and marketplaces.
    string public name;

    /// @notice Contract symbol — informational, for explorers and marketplaces.
    string public symbol;

    /// @notice Off-chain key whose signatures authorise Claim minting.
    address public signer;

    /// @dev Fixed per-tokenId metadata URIs (tokenId 1–5).
    mapping(uint256 => string) private _tokenURIs;

    /// @dev Tracks consumed claimIds — the primary replay guard.
    mapping(bytes32 => bool) private _claimUsed;

    /// @dev Addresses authorised to call burnFragment (intended for RAXAINode).
    mapping(address => bool) public burnOperators;

    /// @dev Addresses authorised to call mintFragment directly (multiple mint admins).
    mapping(address => bool) public mintOperators;

    /// @dev Addresses authorised to initiate transfers (owner + admin contracts).
    mapping(address => bool) public transferOperators;

    // ─── Errors ───────────────────────────────────────────────────────────────

    error InvalidSigner();
    error ClaimAlreadyUsed();
    error InvalidTokenId();
    error UnauthorizedMint();
    error UnauthorizedBurn();
    error TransferNotAllowed();
    error ZeroAddress();

    // ─── Events ───────────────────────────────────────────────────────────────

    /// @notice Emitted on every successful Claim — primary backend reconciliation event.
    event FragmentClaimed(
        bytes32 indexed claimId,
        uint256 indexed tokenId,
        address indexed recipient
    );

    event SignerUpdated(address indexed newSigner);
    event MintOperatorSet(address indexed operator, bool enabled);
    event BurnOperatorSet(address indexed operator, bool enabled);
    event TransferOperatorSet(address indexed operator, bool enabled);

    /// @notice Emitted when fragments are minted via mintFragment (admin direct mint).
    event FragmentMinted(
        address indexed to,
        uint256 indexed tokenId,
        uint256 amount,
        address indexed mintedBy
    );

    /// @notice Emitted when fragments are burned via burnFragment (e.g., during Forge).
    event FragmentBurned(
        address indexed from,
        uint256 indexed tokenId,
        uint256 amount,
        address indexed burnedBy
    );

    /// @notice Emitted when the owner forcibly burns fragments via adminBurnFragment.
    event AdminFragmentBurned(
        address indexed from,
        uint256 indexed tokenId,
        uint256 amount
    );

    // ─── Constructor ──────────────────────────────────────────────────────────

    /// @param initialOwner  EOA that becomes contract owner (admin authority).
    /// @param name_         Contract name — confirmed by ops before deployment.
    /// @param symbol_       Contract symbol — confirmed by ops before deployment.
    /// @param _signer       Address whose private key signs Claim payloads off-chain.
    /// @param tokenURIs_    Fixed metadata URIs for tokenId 1–5 (index 0 → tokenId 1).
    ///                      URIs cannot be updated after deployment.
    constructor(
        address initialOwner,
        string memory name_,
        string memory symbol_,
        address _signer,
        string[5] memory tokenURIs_
    )
        ERC1155("")
        Ownable(initialOwner)
        EIP712("RAXFragments", "1")
    {
        if (_signer == address(0)) revert ZeroAddress();
        name = name_;
        symbol = symbol_;
        signer = _signer;
        for (uint256 i = 0; i < 5; ++i) {
            _tokenURIs[i + 1] = tokenURIs_[i];
        }
    }

    // ─── Admin ────────────────────────────────────────────────────────────────

    /// @notice Replace the off-chain signing key used for Claim verification.
    function setSigner(address _signer) external onlyOwner {
        if (_signer == address(0)) revert ZeroAddress();
        signer = _signer;
        emit SignerUpdated(_signer);
    }

    /// @notice Grant or revoke direct mint authority. Supports multiple mint admins.
    ///         Mint operators can call mintFragment without a user signature.
    ///         Intended for operational use: airdrops, compensation, corrections.
    function setMintOperator(address operator, bool enabled) external onlyOwner {
        if (operator == address(0)) revert ZeroAddress();
        mintOperators[operator] = enabled;
        emit MintOperatorSet(operator, enabled);
    }

    /// @notice Grant or revoke burn authority (intended for RAXAINode contract address).
    function setBurnOperator(address operator, bool enabled) external onlyOwner {
        if (operator == address(0)) revert ZeroAddress();
        burnOperators[operator] = enabled;
        emit BurnOperatorSet(operator, enabled);
    }

    /// @notice Grant or revoke transfer authority (for admin / contract operations).
    function setTransferOperator(address operator, bool enabled) external onlyOwner {
        if (operator == address(0)) revert ZeroAddress();
        transferOperators[operator] = enabled;
        emit TransferOperatorSet(operator, enabled);
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    // ─── Claim ────────────────────────────────────────────────────────────────

    /// @notice Claim a Fragment NFT using an admin-signed EIP-712 payload.
    ///
    ///         Security properties:
    ///         - Signature binds to this contract address and chainId (domain separator).
    ///         - claimId is globally unique and single-use (checked and marked before mint).
    ///         - recipient is embedded in the signature, so front-running only delivers
    ///           the NFT to the correct recipient.
    ///         - Follows Checks-Effects-Interactions: claimId marked used before _mint.
    ///
    /// @param claimId   Unique identifier assigned by the off-chain rewards system.
    /// @param tokenId   Fragment type to mint (1–5).
    /// @param recipient Wallet that receives the Fragment.
    /// @param signature Admin signature over the EIP-712 digest of the above fields.
    function claim(
        bytes32 claimId,
        uint256 tokenId,
        address recipient,
        bytes calldata signature
    ) external whenNotPaused {
        if (tokenId < 1 || tokenId > FRAGMENT_COUNT) revert InvalidTokenId();
        if (_claimUsed[claimId]) revert ClaimAlreadyUsed();

        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(CLAIM_TYPEHASH, claimId, tokenId, recipient))
        );
        if (digest.recover(signature) != signer) revert InvalidSigner();

        // Checks-Effects-Interactions: mark used before external state change (_mint).
        _claimUsed[claimId] = true;
        _mint(recipient, tokenId, 1, "");

        emit FragmentClaimed(claimId, tokenId, recipient);
    }

    // ─── Mint (authorised operators only) ────────────────────────────────────

    /// @notice Directly mint `amount` of fragment `tokenId` to `to`.
    ///         Bypasses the EIP-712 Claim flow — no claimId is consumed.
    ///         Callable only by addresses in mintOperators.
    ///         Intended for operational use: airdrops, compensation, corrections.
    ///         pause does not block this function; operator is trusted.
    function mintFragment(address to, uint256 tokenId, uint256 amount) external {
        if (!mintOperators[msg.sender]) revert UnauthorizedMint();
        if (tokenId < 1 || tokenId > FRAGMENT_COUNT) revert InvalidTokenId();
        _mint(to, tokenId, amount, "");
        emit FragmentMinted(to, tokenId, amount, msg.sender);
    }

    // ─── Burn (authorised operators only) ────────────────────────────────────

    /// @notice Burn `amount` of fragment `tokenId` from `from`.
    ///         Only callable by addresses in burnOperators (expected: RAXAINode contract).
    ///         Called during Forge to atomically consume one of each fragment type.
    function burnFragment(address from, uint256 tokenId, uint256 amount) external {
        if (!burnOperators[msg.sender]) revert UnauthorizedBurn();
        if (tokenId < 1 || tokenId > FRAGMENT_COUNT) revert InvalidTokenId();
        _burn(from, tokenId, amount);
        emit FragmentBurned(from, tokenId, amount, msg.sender);
    }

    // ─── Admin burn ───────────────────────────────────────────────────────────

    /// @notice Owner forcibly burns `amount` of fragment `tokenId` from any address.
    ///         For exceptional operational use only: anomaly handling, compliance removal.
    ///         Emits AdminFragmentBurned for backend reconciliation.
    function adminBurnFragment(address from, uint256 tokenId, uint256 amount) external onlyOwner {
        if (tokenId < 1 || tokenId > FRAGMENT_COUNT) revert InvalidTokenId();
        _burn(from, tokenId, amount);
        emit AdminFragmentBurned(from, tokenId, amount);
    }

    // ─── Metadata ─────────────────────────────────────────────────────────────

    /// @notice Returns the fixed metadata URI for `tokenId`.
    function uri(uint256 tokenId) public view override returns (string memory) {
        if (tokenId < 1 || tokenId > FRAGMENT_COUNT) revert InvalidTokenId();
        return _tokenURIs[tokenId];
    }

    /// @notice Exposes the EIP-712 domain separator — useful for backend signature verification.
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    // ─── Transfer Restriction ─────────────────────────────────────────────────

    /// @dev Owner and transfer operators are treated as universally approved,
    ///      so they can move tokens without prior per-address approval setup.
    function isApprovedForAll(
        address account,
        address operator
    ) public view override returns (bool) {
        if (operator == owner() || transferOperators[operator]) return true;
        return super.isApprovedForAll(account, operator);
    }

    /// @dev Only owner or transfer operators may initiate token transfers.
    ///      Regular user-initiated transfers always revert.
    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) public override {
        if (msg.sender != owner() && !transferOperators[msg.sender]) {
            revert TransferNotAllowed();
        }
        super.safeTransferFrom(from, to, id, amount, data);
    }

    /// @dev Only owner or transfer operators may initiate batch transfers.
    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) public override {
        if (msg.sender != owner() && !transferOperators[msg.sender]) {
            revert TransferNotAllowed();
        }
        super.safeBatchTransferFrom(from, to, ids, amounts, data);
    }

    // ─── View Helpers ─────────────────────────────────────────────────────────

    /// @notice Returns whether a claimId has already been used on-chain.
    function isClaimUsed(bytes32 claimId) external view returns (bool) {
        return _claimUsed[claimId];
    }
}
