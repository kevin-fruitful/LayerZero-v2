// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import { OptionsBuilder } from "../contracts/oapp/libs/OptionsBuilder.sol";

import { OFTFacetMock } from "./mocks/OFTFacetMock.sol";
import { MessagingFee, MessagingReceipt } from "../contracts/oft/OFTCore.sol";
import { OFTAdapterMock } from "./mocks/OFTAdapterMock.sol";
import { ERC20Mock } from "./mocks/ERC20Mock.sol";
import { OFTComposerMock } from "./mocks/OFTComposerMock.sol";
import { OFTInspectorMock, IOAppMsgInspector } from "./mocks/OFTInspectorMock.sol";
import { IOAppOptionsType3, EnforcedOptionParam } from "../contracts/oapp/libs/OAppOptionsType3.sol";

import { OFTMsgCodec } from "../contracts/oft/libs/OFTMsgCodec.sol";
import { OFTComposeMsgCodec } from "../contracts/oft/libs/OFTComposeMsgCodec.sol";

import { IOFT, SendParam, OFTReceipt } from "../contracts/oft/interfaces/IOFT.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

import "forge-std/console.sol";
import { TestHelper } from "./TestHelper.sol";
import "diamond-2-hardhat/Diamond.sol";
import "diamond-2-hardhat/facets/OwnershipFacet.sol";
import "diamond-2-hardhat/facets/DiamondLoupeFacet.sol";
import "diamond-2-hardhat/facets/DiamondCutFacet.sol";
import "../contracts/oft/ERC20Facet.sol";

import "../contracts/oft/OFTFacet.sol";
import "../contracts/oft/interfaces/IOFTDiamond.sol";
import "../contracts/oft/OFTCoreFacet.sol";

import "../contracts/oft/InitDiamond.sol";

import "../contracts/oapp/OApp.sol";
import "../contracts/oapp/OAppReceiverFacet.sol";

struct Addresses {
    address ownershipFacet;
    address diamondLoupeFacet;
    address diamondCutFacet;
    address oftFacet;
    address erc20Facet;
}

library LibDeployDiamond {
    function deployCommonFacets()
        internal
        returns (address ownershipFacet, address diamondLoupeFacet, address diamondCutFacet)
    {
        ownershipFacet = address(new OwnershipFacet());
        diamondLoupeFacet = address(new DiamondLoupeFacet());
        diamondCutFacet = address(new DiamondCutFacet());
    }

    function cutInfoMain(Addresses memory addresses) internal pure returns (IDiamondCut.FacetCut[] memory cut) {
        cut = new IDiamondCut.FacetCut[](5);

        bytes4[] memory functionSelectors = new bytes4[](1);
        functionSelectors[0] = IDiamondCut.diamondCut.selector;
        cut[0] = IDiamondCut.FacetCut({
            facetAddress: addresses.diamondCutFacet,
            action: IDiamondCut.FacetCutAction.Add,
            functionSelectors: functionSelectors
        });

        functionSelectors = new bytes4[](5);
        functionSelectors[0] = IDiamondLoupe.facets.selector;
        functionSelectors[1] = IDiamondLoupe.facetFunctionSelectors.selector;
        functionSelectors[2] = IDiamondLoupe.facetAddresses.selector;
        functionSelectors[3] = IDiamondLoupe.facetAddress.selector;
        functionSelectors[4] = IERC165.supportsInterface.selector;
        cut[1] = IDiamondCut.FacetCut({
            facetAddress: addresses.diamondLoupeFacet,
            action: IDiamondCut.FacetCutAction.Add,
            functionSelectors: functionSelectors
        });

        functionSelectors = new bytes4[](2);
        functionSelectors[0] = IERC173.owner.selector;
        functionSelectors[1] = IERC173.transferOwnership.selector;
        cut[2] = IDiamondCut.FacetCut({
            facetAddress: addresses.ownershipFacet,
            action: IDiamondCut.FacetCutAction.Add,
            functionSelectors: functionSelectors
        });

        functionSelectors = new bytes4[](38);
        functionSelectors[0] = IOFTFacet.SEND.selector;
        functionSelectors[1] = IOFTFacet.SEND_AND_CALL.selector;
        functionSelectors[2] = IOFTFacet.allowInitializePath.selector;
        functionSelectors[3] = IOFTFacet.approvalRequired.selector;
        functionSelectors[4] = IOFTFacet.combineOptions.selector;
        functionSelectors[5] = IOFTFacet.composeMsgSender.selector;
        functionSelectors[6] = IOFTFacet.decimalConversionRate.selector;
        functionSelectors[7] = IOFTFacet.endpoint.selector;
        functionSelectors[8] = IOFTFacet.enforcedOptions.selector;
        functionSelectors[9] = IOFTFacet.isPeer.selector;
        functionSelectors[10] = IOFTFacet.lzReceive.selector;
        functionSelectors[11] = IOFTFacet.lzReceiveAndRevert.selector;
        functionSelectors[12] = IOFTFacet.lzReceiveSimulate.selector;
        functionSelectors[13] = IOFTFacet.nextNonce.selector;
        functionSelectors[14] = IOFTFacet.oApp.selector;
        functionSelectors[15] = IOFTFacet.oAppVersion.selector;
        functionSelectors[16] = IOFTFacet.oftVersion.selector;
        functionSelectors[17] = IOFTFacet.peers.selector;
        functionSelectors[18] = IOFTFacet.preCrime.selector;
        functionSelectors[19] = IOFTFacet.quoteOFT.selector;
        functionSelectors[20] = IOFTFacet.quoteSend.selector;
        functionSelectors[21] = IOFTFacet.send.selector;
        functionSelectors[22] = IOFTFacet.setDelegate.selector;
        functionSelectors[23] = IOFTFacet.setEnforcedOptions.selector;
        functionSelectors[24] = IOFTFacet.setMsgInspector.selector;
        functionSelectors[25] = IOFTFacet.setPeer.selector;
        functionSelectors[26] = IOFTFacet.setPreCrime.selector;
        functionSelectors[27] = IOFTFacet.sharedDecimals.selector;
        functionSelectors[28] = IOFTFacet.token.selector;

        functionSelectors[29] = OFTFacetMock.debit.selector;
        functionSelectors[30] = OFTFacetMock.debitView.selector;
        functionSelectors[31] = OFTFacetMock.removeDust.selector;
        functionSelectors[32] = OFTFacetMock.toLD.selector;
        functionSelectors[33] = OFTFacetMock.toSD.selector;
        functionSelectors[34] = OFTFacetMock.credit.selector;
        functionSelectors[35] = OFTFacetMock.buildMsgAndOptions.selector;
        functionSelectors[36] = OFTFacetMock.mint.selector;

        functionSelectors[37] = IOFTFacet.msgInspector.selector;

        cut[3] = IDiamondCut.FacetCut({
            facetAddress: addresses.oftFacet,
            action: IDiamondCut.FacetCutAction.Add,
            functionSelectors: functionSelectors
        });

        functionSelectors = new bytes4[](9);
        functionSelectors[0] = ERC20Facet.allowance.selector;
        functionSelectors[1] = ERC20Facet.approve.selector;
        functionSelectors[2] = ERC20Facet.balanceOf.selector;
        functionSelectors[3] = ERC20Facet.decimals.selector;
        functionSelectors[4] = ERC20Facet.name.selector;
        functionSelectors[5] = ERC20Facet.symbol.selector;
        functionSelectors[6] = ERC20Facet.totalSupply.selector;
        functionSelectors[7] = ERC20Facet.transfer.selector;
        functionSelectors[8] = ERC20Facet.transferFrom.selector;

        cut[4] = IDiamondCut.FacetCut({
            facetAddress: addresses.erc20Facet,
            action: IDiamondCut.FacetCutAction.Add,
            functionSelectors: functionSelectors
        });
    }
}

contract OFTFacetTest is TestHelper {
    using OptionsBuilder for bytes;

    uint32 aEid = 1;
    uint32 bEid = 2;
    uint32 cEid = 3;

    IOFTDiamond aOFT;
    IOFTDiamond bOFT;
    OFTAdapterMock cOFTAdapter;
    ERC20Mock cERC20Mock;

    OFTInspectorMock oAppInspector;

    address public userA = address(0x1);
    address public userB = address(0x2);
    address public userC = address(0x3);
    uint256 public initialBalance = 100 ether;

    function setUp() public virtual override {
        vm.deal(userA, 1000 ether);
        vm.deal(userB, 1000 ether);
        vm.deal(userC, 1000 ether);

        super.setUp();
        setUpEndpoints(3, LibraryType.UltraLightNode);

        (address ownershipFacet, address diamondLoupeFacet, address diamondCutFacet) =
            LibDeployDiamond.deployCommonFacets();

        address oftFacetMock = address(new OFTFacetMock());

        Addresses memory addresses =
            Addresses(ownershipFacet, diamondLoupeFacet, diamondCutFacet, oftFacetMock, address(new ERC20Facet()));

        IDiamondCut.FacetCut[] memory cut = LibDeployDiamond.cutInfoMain(addresses);

        DiamondArgs memory args = DiamondArgs(
            address(this),
            address(new InitDiamond()),
            abi.encodeCall(InitDiamond.init, (Init({ endpoint: endpoints[aEid], delegate: address(this) })))
        );

        aOFT = IOFTDiamond(address(new Diamond(cut, args)));
        // aOFT.setDelegate(address(this));

        args = DiamondArgs(
            address(this),
            address(new InitDiamond()),
            abi.encodeCall(InitDiamond.init, (Init({ endpoint: endpoints[bEid], delegate: address(this) })))
        );

        bOFT = IOFTDiamond(address(new Diamond(cut, args)));
        // bOFT.setDelegate(address(this));

        cERC20Mock = new ERC20Mock("cToken", "cToken");
        cOFTAdapter = OFTAdapterMock(
            _deployOApp(
                type(OFTAdapterMock).creationCode,
                abi.encode(address(cERC20Mock), address(endpoints[cEid]), address(this))
            )
        );

        // config and wire the ofts
        address[] memory ofts = new address[](3);
        ofts[0] = address(aOFT);
        ofts[1] = address(bOFT);
        ofts[2] = address(cOFTAdapter);
        this.wireOApps(ofts);

        // mint tokens
        aOFT.mint(userA, initialBalance);
        bOFT.mint(userB, initialBalance);
        cERC20Mock.mint(userC, initialBalance);

        // deploy a universal inspector, can be used by each oft
        oAppInspector = new OFTInspectorMock();
    }

    function test_constructor() public {
        assertEq(aOFT.owner(), address(this));
        assertEq(bOFT.owner(), address(this));
        assertEq(cOFTAdapter.owner(), address(this));

        assertEq(aOFT.balanceOf(userA), initialBalance);
        assertEq(bOFT.balanceOf(userB), initialBalance);
        assertEq(IERC20(cOFTAdapter.token()).balanceOf(userC), initialBalance);

        assertEq(aOFT.token(), address(aOFT));
        assertEq(bOFT.token(), address(bOFT));
        assertEq(cOFTAdapter.token(), address(cERC20Mock));
    }

    function test_oftVersion() public {
        (bytes4 interfaceId,) = aOFT.oftVersion();
        bytes4 expectedId = 0x02e49c2c;
        assertEq(interfaceId, expectedId);
    }

    function test_send_oft() public {
        uint256 tokensToSend = 1 ether;
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200_000, 0);
        SendParam memory sendParam =
            SendParam(bEid, addressToBytes32(userB), tokensToSend, tokensToSend, options, "", "");
        MessagingFee memory fee = aOFT.quoteSend(sendParam, false);

        assertEq(aOFT.balanceOf(userA), initialBalance);
        assertEq(bOFT.balanceOf(userB), initialBalance);

        vm.prank(userA);
        aOFT.send{ value: fee.nativeFee }(sendParam, fee, payable(address(this)));
        verifyPackets(bEid, addressToBytes32(address(bOFT)));

        assertEq(aOFT.balanceOf(userA), initialBalance - tokensToSend);
        assertEq(bOFT.balanceOf(userB), initialBalance + tokensToSend);
    }

    function test_send_oft_compose_msg() public {
        uint256 tokensToSend = 1 ether;

        OFTComposerMock composer = new OFTComposerMock();

        bytes memory options =
            OptionsBuilder.newOptions().addExecutorLzReceiveOption(200_000, 0).addExecutorLzComposeOption(0, 500_000, 0);
        bytes memory composeMsg = hex"1234";
        SendParam memory sendParam =
            SendParam(bEid, addressToBytes32(address(composer)), tokensToSend, tokensToSend, options, composeMsg, "");
        MessagingFee memory fee = aOFT.quoteSend(sendParam, false);

        assertEq(aOFT.balanceOf(userA), initialBalance);
        assertEq(bOFT.balanceOf(address(composer)), 0);

        vm.prank(userA);
        (MessagingReceipt memory msgReceipt, OFTReceipt memory oftReceipt) =
            aOFT.send{ value: fee.nativeFee }(sendParam, fee, payable(address(this)));
        verifyPackets(bEid, addressToBytes32(address(bOFT)));

        // lzCompose params
        uint32 dstEid_ = bEid;
        address from_ = address(bOFT);
        bytes memory options_ = options;
        bytes32 guid_ = msgReceipt.guid;
        address to_ = address(composer);
        bytes memory composerMsg_ = OFTComposeMsgCodec.encode(
            msgReceipt.nonce, aEid, oftReceipt.amountReceivedLD, abi.encodePacked(addressToBytes32(userA), composeMsg)
        );
        this.lzCompose(dstEid_, from_, options_, guid_, to_, composerMsg_);

        assertEq(aOFT.balanceOf(userA), initialBalance - tokensToSend);
        assertEq(bOFT.balanceOf(address(composer)), tokensToSend);

        assertEq(composer.from(), from_);
        assertEq(composer.guid(), guid_);
        assertEq(composer.message(), composerMsg_);
        assertEq(composer.executor(), address(this));
        assertEq(composer.extraData(), composerMsg_); // default to setting the extraData to the message as well to test
    }

    function test_oft_compose_codec() public {
        uint64 nonce = 1;
        uint32 srcEid = 2;
        uint256 amountCreditLD = 3;
        bytes memory composeMsg = hex"1234";

        bytes memory message = OFTComposeMsgCodec.encode(
            nonce, srcEid, amountCreditLD, abi.encodePacked(addressToBytes32(msg.sender), composeMsg)
        );
        (uint64 nonce_, uint32 srcEid_, uint256 amountCreditLD_, bytes32 composeFrom_, bytes memory composeMsg_) =
            this.decodeOFTComposeMsgCodec(message);

        assertEq(nonce_, nonce);
        assertEq(srcEid_, srcEid);
        assertEq(amountCreditLD_, amountCreditLD);
        assertEq(composeFrom_, addressToBytes32(msg.sender));
        assertEq(composeMsg_, composeMsg);
    }

    function decodeOFTComposeMsgCodec(bytes calldata message)
        public
        pure
        returns (uint64 nonce, uint32 srcEid, uint256 amountCreditLD, bytes32 composeFrom, bytes memory composeMsg)
    {
        nonce = OFTComposeMsgCodec.nonce(message);
        srcEid = OFTComposeMsgCodec.srcEid(message);
        amountCreditLD = OFTComposeMsgCodec.amountLD(message);
        composeFrom = OFTComposeMsgCodec.composeFrom(message);
        composeMsg = OFTComposeMsgCodec.composeMsg(message);
    }

    function test_debit_slippage_removeDust() public {
        uint256 amountToSendLD = 1.23456789 ether;
        uint256 minAmountToCreditLD = 1.23456789 ether;
        uint32 dstEid = aEid;

        // remove the dust form the shared decimal conversion
        assertEq(aOFT.removeDust(amountToSendLD), 1.234567 ether);

        vm.expectRevert(
            abi.encodeWithSelector(IOFT.SlippageExceeded.selector, aOFT.removeDust(amountToSendLD), minAmountToCreditLD)
        );
        aOFT.debit(amountToSendLD, minAmountToCreditLD, dstEid);
    }

    function test_debit_slippage_minAmountToCreditLD() public {
        uint256 amountToSendLD = 1 ether;
        uint256 minAmountToCreditLD = 1.00000001 ether;
        uint32 dstEid = aEid;

        vm.expectRevert(abi.encodeWithSelector(IOFT.SlippageExceeded.selector, amountToSendLD, minAmountToCreditLD));
        aOFT.debit(amountToSendLD, minAmountToCreditLD, dstEid);
    }

    function test_toLD() public {
        uint64 amountSD = 1000;
        assertEq(amountSD * aOFT.decimalConversionRate(), aOFT.toLD(uint64(amountSD)));
    }

    function test_toSD() public {
        uint256 amountLD = 1_000_000;
        assertEq(amountLD / aOFT.decimalConversionRate(), aOFT.toSD(amountLD));
    }

    function test_oft_debit() public {
        uint256 amountToSendLD = 1 ether;
        uint256 minAmountToCreditLD = 1 ether;
        uint32 dstEid = aEid;

        assertEq(aOFT.balanceOf(userA), initialBalance);
        assertEq(aOFT.balanceOf(address(this)), 0);

        vm.prank(userA);
        (uint256 amountDebitedLD, uint256 amountToCreditLD) = aOFT.debit(amountToSendLD, minAmountToCreditLD, dstEid);

        assertEq(amountDebitedLD, amountToSendLD);
        assertEq(amountToCreditLD, amountToSendLD);

        assertEq(aOFT.balanceOf(userA), initialBalance - amountToSendLD);
        assertEq(aOFT.balanceOf(address(this)), 0);
    }

    function test_oft_credit() public {
        uint256 amountToCreditLD = 1 ether;
        uint32 srcEid = aEid;

        assertEq(aOFT.balanceOf(userA), initialBalance);
        assertEq(aOFT.balanceOf(address(this)), 0);

        vm.prank(userA);
        uint256 amountReceived = aOFT.credit(userA, amountToCreditLD, srcEid);

        assertEq(aOFT.balanceOf(userA), initialBalance + amountReceived);
        assertEq(aOFT.balanceOf(address(this)), 0);
    }

    function test_oft_adapter_debit() public {
        uint256 amountToSendLD = 1 ether;
        uint256 minAmountToCreditLD = 1 ether;
        uint32 dstEid = cEid;

        assertEq(cERC20Mock.balanceOf(userC), initialBalance);
        assertEq(cERC20Mock.balanceOf(address(cOFTAdapter)), 0);

        vm.prank(userC);
        vm.expectRevert(abi.encodeWithSelector(IOFT.SlippageExceeded.selector, amountToSendLD, minAmountToCreditLD + 1));
        cOFTAdapter.debitView(amountToSendLD, minAmountToCreditLD + 1, dstEid);

        vm.prank(userC);
        cERC20Mock.approve(address(cOFTAdapter), amountToSendLD);
        vm.prank(userC);
        (uint256 amountDebitedLD, uint256 amountToCreditLD) =
            cOFTAdapter.debit(amountToSendLD, minAmountToCreditLD, dstEid);

        assertEq(amountDebitedLD, amountToSendLD);
        assertEq(amountToCreditLD, amountToSendLD);

        assertEq(cERC20Mock.balanceOf(userC), initialBalance - amountToSendLD);
        assertEq(cERC20Mock.balanceOf(address(cOFTAdapter)), amountToSendLD);
    }

    function test_oft_adapter_credit() public {
        uint256 amountToCreditLD = 1 ether;
        uint32 srcEid = cEid;

        assertEq(cERC20Mock.balanceOf(userC), initialBalance);
        assertEq(cERC20Mock.balanceOf(address(cOFTAdapter)), 0);

        vm.prank(userC);
        cERC20Mock.transfer(address(cOFTAdapter), amountToCreditLD);

        uint256 amountReceived = cOFTAdapter.credit(userB, amountToCreditLD, srcEid);

        assertEq(cERC20Mock.balanceOf(userC), initialBalance - amountToCreditLD);
        assertEq(cERC20Mock.balanceOf(address(userB)), amountReceived);
        assertEq(cERC20Mock.balanceOf(address(cOFTAdapter)), 0);
    }

    function decodeOFTMsgCodec(bytes calldata message)
        public
        pure
        returns (bool isComposed, bytes32 sendTo, uint64 amountSD, bytes memory composeMsg)
    {
        isComposed = OFTMsgCodec.isComposed(message);
        sendTo = OFTMsgCodec.sendTo(message);
        amountSD = OFTMsgCodec.amountSD(message);
        composeMsg = OFTMsgCodec.composeMsg(message);
    }

    function test_oft_build_msg() public {
        uint32 dstEid = bEid;
        bytes32 to = addressToBytes32(userA);
        uint256 amountToSendLD = 1.23456789 ether;
        uint256 minAmountToCreditLD = aOFT.removeDust(amountToSendLD);

        // params for buildMsgAndOptions
        bytes memory extraOptions = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200_000, 0);
        bytes memory composeMsg = hex"1234";
        SendParam memory sendParam =
            SendParam(dstEid, to, amountToSendLD, minAmountToCreditLD, extraOptions, composeMsg, "");
        uint256 amountToCreditLD = minAmountToCreditLD;

        (bytes memory message,) = aOFT.buildMsgAndOptions(sendParam, amountToCreditLD);

        (bool isComposed_, bytes32 sendTo_, uint64 amountSD_, bytes memory composeMsg_) =
            this.decodeOFTMsgCodec(message);

        assertEq(isComposed_, true);
        assertEq(sendTo_, to);
        assertEq(amountSD_, aOFT.toSD(amountToCreditLD));
        bytes memory expectedComposeMsg = abi.encodePacked(addressToBytes32(address(this)), composeMsg);
        assertEq(composeMsg_, expectedComposeMsg);
    }

    function test_oft_build_msg_no_compose_msg() public {
        uint32 dstEid = bEid;
        bytes32 to = addressToBytes32(userA);
        uint256 amountToSendLD = 1.23456789 ether;
        uint256 minAmountToCreditLD = aOFT.removeDust(amountToSendLD);

        // params for buildMsgAndOptions
        bytes memory extraOptions = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200_000, 0);
        bytes memory composeMsg = "";
        SendParam memory sendParam =
            SendParam(dstEid, to, amountToSendLD, minAmountToCreditLD, extraOptions, composeMsg, "");
        uint256 amountToCreditLD = minAmountToCreditLD;

        (bytes memory message,) = aOFT.buildMsgAndOptions(sendParam, amountToCreditLD);

        (bool isComposed_, bytes32 sendTo_, uint64 amountSD_, bytes memory composeMsg_) =
            this.decodeOFTMsgCodec(message);

        assertEq(isComposed_, false);
        assertEq(sendTo_, to);
        assertEq(amountSD_, aOFT.toSD(amountToCreditLD));
        assertEq(composeMsg_, "");
    }

    function test_set_enforced_options() public {
        uint32 eid = 1;

        bytes memory optionsTypeOne = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200_000, 0);
        bytes memory optionsTypeTwo = OptionsBuilder.newOptions().addExecutorLzReceiveOption(250_000, 0);

        EnforcedOptionParam[] memory enforcedOptions = new EnforcedOptionParam[](2);
        enforcedOptions[0] = EnforcedOptionParam(eid, 1, optionsTypeOne);
        enforcedOptions[1] = EnforcedOptionParam(eid, 2, optionsTypeTwo);

        aOFT.setEnforcedOptions(enforcedOptions);

        assertEq(aOFT.enforcedOptions(eid, 1), optionsTypeOne);
        assertEq(aOFT.enforcedOptions(eid, 2), optionsTypeTwo);
    }

    function test_assert_options_type3_revert() public {
        uint32 eid = 1;
        EnforcedOptionParam[] memory enforcedOptions = new EnforcedOptionParam[](1);

        enforcedOptions[0] = EnforcedOptionParam(eid, 1, hex"0004"); // not type 3
        vm.expectRevert(abi.encodeWithSelector(IOAppOptionsType3.InvalidOptions.selector, hex"0004"));
        aOFT.setEnforcedOptions(enforcedOptions);

        enforcedOptions[0] = EnforcedOptionParam(eid, 1, hex"0002"); // not type 3
        vm.expectRevert(abi.encodeWithSelector(IOAppOptionsType3.InvalidOptions.selector, hex"0002"));
        aOFT.setEnforcedOptions(enforcedOptions);

        enforcedOptions[0] = EnforcedOptionParam(eid, 1, hex"0001"); // not type 3
        vm.expectRevert(abi.encodeWithSelector(IOAppOptionsType3.InvalidOptions.selector, hex"0001"));
        aOFT.setEnforcedOptions(enforcedOptions);

        enforcedOptions[0] = EnforcedOptionParam(eid, 1, hex"0003"); // IS type 3
        aOFT.setEnforcedOptions(enforcedOptions); // doesnt revert cus option type 3
    }

    function test_combine_options() public {
        uint32 eid = 1;
        uint16 msgType = 1;

        bytes memory enforcedOptions = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200_000, 0);
        EnforcedOptionParam[] memory enforcedOptionsArray = new EnforcedOptionParam[](1);
        enforcedOptionsArray[0] = EnforcedOptionParam(eid, msgType, enforcedOptions);
        aOFT.setEnforcedOptions(enforcedOptionsArray);

        bytes memory extraOptions =
            OptionsBuilder.newOptions().addExecutorNativeDropOption(1.2345 ether, addressToBytes32(userA));

        bytes memory expectedOptions = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200_000, 0)
            .addExecutorNativeDropOption(1.2345 ether, addressToBytes32(userA));

        bytes memory combinedOptions = aOFT.combineOptions(eid, msgType, extraOptions);
        assertEq(combinedOptions, expectedOptions);
    }

    function test_combine_options_no_extra_options() public {
        uint32 eid = 1;
        uint16 msgType = 1;

        bytes memory enforcedOptions = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200_000, 0);
        EnforcedOptionParam[] memory enforcedOptionsArray = new EnforcedOptionParam[](1);
        enforcedOptionsArray[0] = EnforcedOptionParam(eid, msgType, enforcedOptions);
        aOFT.setEnforcedOptions(enforcedOptionsArray);

        bytes memory expectedOptions = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200_000, 0);

        bytes memory combinedOptions = aOFT.combineOptions(eid, msgType, "");
        assertEq(combinedOptions, expectedOptions);
    }

    function test_combine_options_no_enforced_options() public {
        uint32 eid = 1;
        uint16 msgType = 1;

        bytes memory extraOptions =
            OptionsBuilder.newOptions().addExecutorNativeDropOption(1.2345 ether, addressToBytes32(userA));

        bytes memory expectedOptions =
            OptionsBuilder.newOptions().addExecutorNativeDropOption(1.2345 ether, addressToBytes32(userA));

        bytes memory combinedOptions = aOFT.combineOptions(eid, msgType, extraOptions);
        assertEq(combinedOptions, expectedOptions);
    }

    function test_oapp_inspector_inspect() public {
        uint32 dstEid = bEid;
        bytes32 to = addressToBytes32(userA);
        uint256 amountToSendLD = 1.23456789 ether;
        uint256 minAmountToCreditLD = aOFT.removeDust(amountToSendLD);

        // params for buildMsgAndOptions
        bytes memory extraOptions = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200_000, 0);
        bytes memory composeMsg = "";
        SendParam memory sendParam =
            SendParam(dstEid, to, amountToSendLD, minAmountToCreditLD, extraOptions, composeMsg, "");
        uint256 amountToCreditLD = minAmountToCreditLD;

        // doesnt revert
        (bytes memory message,) = aOFT.buildMsgAndOptions(sendParam, amountToCreditLD);

        // deploy a universal inspector, it automatically reverts
        oAppInspector = new OFTInspectorMock();
        // set the inspector
        aOFT.setMsgInspector(address(oAppInspector));

        // does revert because inspector is set
        vm.expectRevert(abi.encodeWithSelector(IOAppMsgInspector.InspectionFailed.selector, message, extraOptions));
        (message,) = aOFT.buildMsgAndOptions(sendParam, amountToCreditLD);
    }
}
