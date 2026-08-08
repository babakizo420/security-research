// SPDX-License-Identifier: GPL-2.0-or-later
// cycle802 audit-drift harness (Buddy / Securva) - NOT part of the Morpho repo.
// Target: src/periphery/blue-public-allocator/BluePublicAllocator.sol
// This periphery contract is fresh (built Jul-2026), permissionless, and absent from the audits/ list.
// We empirically test the two security promises a permissionless fund-mover must keep:
//   INV-B  a permissionless caller can NEVER push a market's allocation past the caps (public + vault).
//   INV-C  a permissionless allocateFromIdle does NOT change totalAssets or the share price (value conservation).
pragma solidity ^0.8.0;

import "../lib/forge-std/src/Test.sol";
import {VaultV2Factory} from "../src/VaultV2Factory.sol";
import {VaultV2, WAD} from "../src/VaultV2.sol";
import {IVaultV2} from "../src/interfaces/IVaultV2.sol";
import {IVaultV2Factory} from "../src/interfaces/IVaultV2Factory.sol";
import {BluePublicAllocator} from "../src/periphery/blue-public-allocator/BluePublicAllocator.sol";
import {IBluePublicAllocator} from "../src/periphery/blue-public-allocator/interfaces/IBluePublicAllocator.sol";
import {MorphoMarketV1AdapterV2} from "../src/adapters/MorphoMarketV1AdapterV2.sol";
import {MorphoMarketV1AdapterV2Factory} from "../src/adapters/MorphoMarketV1AdapterV2Factory.sol";
import {IMorphoMarketV1AdapterV2} from "../src/adapters/interfaces/IMorphoMarketV1AdapterV2.sol";
import {ERC20Mock} from "./mocks/ERC20Mock.sol";
import {OracleMock} from "../lib/morpho-blue/src/mocks/OracleMock.sol";
import {IMorpho, MarketParams, Id} from "../lib/morpho-blue/src/interfaces/IMorpho.sol";
import {MarketParamsLib} from "../lib/morpho-blue/src/libraries/MarketParamsLib.sol";
import {IAdaptiveCurveIrm} from "../lib/morpho-blue-irm/src/adaptive-curve-irm/interfaces/IAdaptiveCurveIrm.sol";

contract DriftBluePublicAllocatorTest is Test {
    using MarketParamsLib for MarketParams;

    address owner = makeAddr("owner");
    address curator = makeAddr("curator");
    address allocator = makeAddr("allocator");
    address attacker = makeAddr("attacker");
    address depositor = makeAddr("depositor");

    ERC20Mock loanToken;
    ERC20Mock collateralToken;
    IMorpho morpho;
    IAdaptiveCurveIrm irm;
    OracleMock oracle;
    MarketParams marketParams;

    VaultV2 vault;
    MorphoMarketV1AdapterV2 adapter;
    BluePublicAllocator pub;

    function _execTimelocked(bytes memory call) internal {
        vm.prank(curator);
        vault.submit(call);
        (bool ok,) = address(vault).call(call);
        require(ok, "exec failed");
    }

    function setUp() public {
        // ----- Morpho Blue + market -----
        address morphoOwner = makeAddr("MorphoOwner");
        morpho = IMorpho(deployCode("Morpho.sol", abi.encode(morphoOwner)));
        loanToken = new ERC20Mock(18);
        collateralToken = new ERC20Mock(18);
        oracle = new OracleMock();
        oracle.setPrice(1e36);
        irm = IAdaptiveCurveIrm(deployCode("AdaptiveCurveIrm.sol", abi.encode(address(morpho))));

        marketParams = MarketParams({
            loanToken: address(loanToken),
            collateralToken: address(collateralToken),
            irm: address(irm),
            oracle: address(oracle),
            lltv: 0.8 ether
        });
        vm.startPrank(morphoOwner);
        morpho.enableIrm(address(irm));
        morpho.enableLltv(0.8 ether);
        vm.stopPrank();
        morpho.createMarket(marketParams);

        // seed the market so it is not empty (inflation-attack protection assumption)
        deal(address(loanToken), address(this), 1e18);
        loanToken.approve(address(morpho), type(uint256).max);
        morpho.supply(marketParams, 1e18, 0, address(this), hex"");

        // ----- Vault V2 + adapter -----
        IVaultV2Factory vf = IVaultV2Factory(address(new VaultV2Factory()));
        vault = VaultV2(vf.createVaultV2(owner, address(loanToken), bytes32(0)));
        vm.prank(owner);
        vault.setCurator(curator);

        adapter = MorphoMarketV1AdapterV2(
            new MorphoMarketV1AdapterV2Factory(address(morpho), address(irm)).createMorphoMarketV1AdapterV2(
                address(vault)
            )
        );

        pub = new BluePublicAllocator();

        // curator: register adapter, allocators (human + the public allocator), and caps for all 3 adapter ids
        _execTimelocked(abi.encodeCall(IVaultV2.addAdapter, (address(adapter))));
        _execTimelocked(abi.encodeCall(IVaultV2.setIsAllocator, (allocator, true)));
        _execTimelocked(abi.encodeCall(IVaultV2.setIsAllocator, (address(pub), true)));

        _capAll();

        // depositor funds the vault (idle liquidity)
        deal(address(loanToken), depositor, 1_000e18);
        vm.startPrank(depositor);
        loanToken.approve(address(vault), type(uint256).max);
        vault.deposit(1_000e18, depositor);
        vm.stopPrank();
    }

    function _capAll() internal {
        bytes memory idAdapter = abi.encode("this", address(adapter));
        bytes memory idCollateral = abi.encode("collateralToken", marketParams.collateralToken);
        bytes memory idMarket = abi.encode("this/marketParams", address(adapter), marketParams);
        _increaseAbsoluteCap(idAdapter, type(uint128).max);
        _increaseAbsoluteCap(idCollateral, type(uint128).max);
        _increaseAbsoluteCap(idMarket, type(uint128).max);
        // relativeCap defaults to 0 which blocks all allocation; set to WAD (100%) so the ABSOLUTE cap is the binding constraint under test.
        _increaseRelativeCap(idAdapter, WAD);
        _increaseRelativeCap(idCollateral, WAD);
        _increaseRelativeCap(idMarket, WAD);
    }

    function _increaseRelativeCap(bytes memory idData, uint256 cap) internal {
        vm.prank(curator);
        vault.submit(abi.encodeCall(IVaultV2.increaseRelativeCap, (idData, cap)));
        vault.increaseRelativeCap(idData, cap);
    }

    function _increaseAbsoluteCap(bytes memory idData, uint256 cap) internal {
        vm.prank(curator);
        vault.submit(abi.encodeCall(IVaultV2.increaseAbsoluteCap, (idData, cap)));
        vault.increaseAbsoluteCap(idData, cap);
    }

    function _marketAllocationId() internal view returns (bytes32) {
        return keccak256(abi.encode("this/marketParams", address(adapter), marketParams));
    }

    // The allocator wires the public allocator: active adapter, an absolute cap of PUBCAP, and canAllocateFromIdle.
    function _wirePublic(uint256 pubCap) internal {
        vm.startPrank(allocator);
        pub.setIsActiveAdapter(address(vault), address(adapter), true);
        pub.setAbsoluteCap(address(vault), address(adapter), marketParams, pubCap);
        pub.setCanAllocateFromIdle(address(vault), true);
        vm.stopPrank();
    }

    // INV-B: a permissionless caller cannot exceed the public allocator's absolute cap.
    function testInvB_permissionlessCannotExceedPublicCap(uint256 pubCap, uint256 want) public {
        pubCap = bound(pubCap, 1e18, 500e18);
        want = bound(want, 1, 500e18);
        _wirePublic(pubCap);

        bytes32 id = _marketAllocationId();

        if (want <= pubCap) {
            vm.prank(attacker);
            pub.allocateFromIdle(address(vault), address(adapter), marketParams, uint128(want));
            assertLe(vault.allocation(id), pubCap, "allocation exceeded public cap");
        } else {
            vm.prank(attacker);
            vm.expectRevert(IBluePublicAllocator.AbsoluteCapExceeded.selector);
            pub.allocateFromIdle(address(vault), address(adapter), marketParams, uint128(want));
        }
    }

    // INV-B2: even repeated permissionless calls can never push allocation past the cap.
    function testInvB2_repeatedCallsStayUnderCap() public {
        uint256 pubCap = 100e18;
        _wirePublic(pubCap);
        bytes32 id = _marketAllocationId();

        vm.startPrank(attacker);
        pub.allocateFromIdle(address(vault), address(adapter), marketParams, 60e18);
        assertLe(vault.allocation(id), pubCap);
        // second call that would breach the cap must revert, leaving state unchanged
        vm.expectRevert(IBluePublicAllocator.AbsoluteCapExceeded.selector);
        pub.allocateFromIdle(address(vault), address(adapter), marketParams, 60e18);
        vm.stopPrank();
        assertLe(vault.allocation(id), pubCap, "allocation exceeded cap after repeated calls");
    }

    // INV-C: a permissionless allocateFromIdle conserves value (no change to totalAssets or share price).
    function testInvC_permissionlessAllocateConservesValue(uint256 want) public {
        want = bound(want, 1e18, 500e18);
        _wirePublic(600e18);

        uint256 taBefore = vault.totalAssets();
        uint256 shares = vault.balanceOf(depositor);
        uint256 assetsBefore = vault.convertToAssets(shares);

        vm.prank(attacker);
        pub.allocateFromIdle(address(vault), address(adapter), marketParams, uint128(want));

        uint256 taAfter = vault.totalAssets();
        uint256 assetsAfter = vault.convertToAssets(shares);

        // moving idle -> market must not create or destroy vault value (allow 1 wei rounding).
        assertApproxEqAbs(taAfter, taBefore, 1, "totalAssets drifted on permissionless allocate");
        assertLe(assetsAfter, assetsBefore + 1, "depositor value increased out of thin air");
        assertGe(assetsAfter + 1e12, assetsBefore, "depositor value destroyed beyond dust");
    }
}
