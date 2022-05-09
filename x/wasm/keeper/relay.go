package keeper

import (
	"time"

	wasmvmtypes "github.com/CosmWasm/wasmvm/types"
	"github.com/cosmos/cosmos-sdk/store/prefix"
	"github.com/cosmos/cosmos-sdk/telemetry"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"

	"github.com/terra-money/core/x/wasm/types"
)

var _ types.IBCContractKeeper = (*Keeper)(nil)

// OnOpenChannel calls the contract to participate in the IBC channel handshake step.
// In the IBC protocol this is either the `Channel Open Init` event on the initiating chain or
// `Channel Open Try` on the counterparty chain.
// Protocol version and channel ordering should be verified for example.
// See https://github.com/cosmos/ics/tree/master/spec/ics-004-channel-and-packet-semantics#channel-lifecycle-management
func (k Keeper) OnOpenChannel(
	ctx sdk.Context,
	contractAddr sdk.AccAddress,
	msg wasmvmtypes.IBCChannelOpenMsg,
) error {
	defer telemetry.MeasureSince(time.Now(), "wasm", "contract", "ibc-open-channel")

	contractInfo, err := k.GetContractInfo(ctx, contractAddr)
	if err != nil {
		return err
	}

	codeInfo, err := k.GetCodeInfo(ctx, contractInfo.GetCodeID())
	if err != nil {
		return err
	}

	storeKey := types.GetContractStoreKey(contractAddr)
	store := prefix.NewStore(ctx.KVStore(k.storeKey), storeKey)

	env := types.NewEnv(ctx, contractAddr)
	querier := types.NewWasmQuerier()

	gas := k.getWasmVMGasRemaining(ctx)
	gasUsed, execErr := k.wasmVM.IBCChannelOpen(codeInfo.CodeHash, env, msg, store, k.getCosmWasmAPI(), querier, ctx.GasMeter(), gas, types.JSONDeserializationWasmGasCost)
	k.consumeWasmVMGas(ctx, gasUsed, "ibc channel open")
	if execErr != nil {
		return sdkerrors.Wrap(types.ErrExecuteFailed, execErr.Error())
	}

	// there's no result. so don't need to handle response.
	return nil
}

// OnConnectChannel calls the contract to let it know the IBC channel was established.
// In the IBC protocol this is either the `Channel Open Ack` event on the initiating chain or
// `Channel Open Confirm` on the counterparty chain.
//
// There is an open issue with the [cosmos-sdk](https://github.com/cosmos/cosmos-sdk/issues/8334)
// that the counterparty channelID is empty on the initiating chain
// See https://github.com/cosmos/ics/tree/master/spec/ics-004-channel-and-packet-semantics#channel-lifecycle-management
func (k Keeper) OnConnectChannel(
	ctx sdk.Context,
	contractAddr sdk.AccAddress,
	msg wasmvmtypes.IBCChannelConnectMsg,
) error {
	defer telemetry.MeasureSince(time.Now(), "wasm", "contract", "ibc-connect-channel")

	contractInfo, err := k.GetContractInfo(ctx, contractAddr)
	if err != nil {
		return err
	}

	codeInfo, err := k.GetCodeInfo(ctx, contractInfo.GetCodeID())
	if err != nil {
		return err
	}

	storeKey := types.GetContractStoreKey(contractAddr)
	store := prefix.NewStore(ctx.KVStore(k.storeKey), storeKey)

	env := types.NewEnv(ctx, contractAddr)
	querier := types.NewWasmQuerier()

	gas := k.getWasmVMGasRemaining(ctx)
	res, gasUsed, execErr := k.wasmVM.IBCChannelConnect(codeInfo.CodeHash, env, msg, store, k.getCosmWasmAPI(), querier, ctx.GasMeter(), gas, types.JSONDeserializationWasmGasCost)
	k.consumeWasmVMGas(ctx, gasUsed, "ibc channel connect")
	if execErr != nil {
		return sdkerrors.Wrap(types.ErrExecuteFailed, execErr.Error())
	}

	///
	// consume gas for wasm events
	ctx.GasMeter().ConsumeGas(types.EventCosts(res.Attributes, res.Events), "Event Cost")

	// emitting events, dispatching submessages	are done in handleIBCBasicContractResponse()
	return k.handleIBCBasicContractResponse(ctx, contractAddr, contractInfo.IBCPortID, res)

}

// OnCloseChannel calls the contract to let it know the IBC channel is closed.
// Calling modules MAY atomically execute appropriate application logic in conjunction with calling chanCloseConfirm.
//
// Once closed, channels cannot be reopened and identifiers cannot be reused. Identifier reuse is prevented because
// we want to prevent potential replay of previously sent packets
// See https://github.com/cosmos/ics/tree/master/spec/ics-004-channel-and-packet-semantics#channel-lifecycle-management
func (k Keeper) OnCloseChannel(
	ctx sdk.Context,
	contractAddr sdk.AccAddress,
	msg wasmvmtypes.IBCChannelCloseMsg,
) error {
	defer telemetry.MeasureSince(time.Now(), "wasm", "contract", "ibc-close-channel")

	contractInfo, err := k.GetContractInfo(ctx, contractAddr)
	if err != nil {
		return err
	}

	codeInfo, err := k.GetCodeInfo(ctx, contractInfo.GetCodeID())
	if err != nil {
		return err
	}

	storeKey := types.GetContractStoreKey(contractAddr)
	store := prefix.NewStore(ctx.KVStore(k.storeKey), storeKey)

	env := types.NewEnv(ctx, contractAddr)
	querier := types.NewWasmQuerier()

	gas := k.getWasmVMGasRemaining(ctx)
	res, gasUsed, execErr := k.wasmVM.IBCChannelClose(codeInfo.CodeHash, env, msg, store, k.getCosmWasmAPI(), querier, ctx.GasMeter(), gas, types.JSONDeserializationWasmGasCost)
	k.consumeWasmVMGas(ctx, gasUsed, "ibc channel close")
	if execErr != nil {
		return sdkerrors.Wrap(types.ErrExecuteFailed, execErr.Error())
	}

	// emitting events, dispatching submessages	are done in handleIBCBasicContractResponse()
	return k.handleIBCBasicContractResponse(ctx, contractAddr, contractInfo.IBCPortID, res)
}

// OnRecvPacket calls the contract to process the incoming IBC packet. The contract fully owns the data processing and
// returns the acknowledgement data for the chain level. This allows custom applications and protocols on top
// of IBC. Although it is recommended to use the standard acknowledgement envelope defined in
// https://github.com/cosmos/ics/tree/master/spec/ics-004-channel-and-packet-semantics#acknowledgement-envelope
//
// For more information see: https://github.com/cosmos/ics/tree/master/spec/ics-004-channel-and-packet-semantics#packet-flow--handling
func (k Keeper) OnRecvPacket(
	ctx sdk.Context,
	contractAddr sdk.AccAddress,
	msg wasmvmtypes.IBCPacketReceiveMsg,
) ([]byte, error) {
	defer telemetry.MeasureSince(time.Now(), "wasm", "contract", "ibc-recv-packet")

	contractInfo, err := k.GetContractInfo(ctx, contractAddr)
	if err != nil {
		return nil, err
	}

	codeInfo, err := k.GetCodeInfo(ctx, contractInfo.GetCodeID())
	if err != nil {
		return nil, err
	}

	storeKey := types.GetContractStoreKey(contractAddr)
	store := prefix.NewStore(ctx.KVStore(k.storeKey), storeKey)

	env := types.NewEnv(ctx, contractAddr)
	querier := types.NewWasmQuerier()

	gas := k.getWasmVMGasRemaining(ctx)
	res, gasUsed, execErr := k.wasmVM.IBCPacketReceive(codeInfo.CodeHash, env, msg, store, k.getCosmWasmAPI(), querier, ctx.GasMeter(), gas, types.JSONDeserializationWasmGasCost)
	k.consumeWasmVMGas(ctx, gasUsed, "ibc packet recv")
	if execErr != nil {
		return nil, sdkerrors.Wrap(types.ErrExecuteFailed, execErr.Error())
	}
	if res.Err != "" { // handle error case as before https://github.com/CosmWasm/wasmvm/commit/c300106fe5c9426a495f8e10821e00a9330c56c6
		return nil, sdkerrors.Wrap(types.ErrExecuteFailed, res.Err)
	}
	// note submessage reply results can overwrite the `Acknowledgement` data
	return k.handleIBCContractResponse(ctx, contractAddr, contractInfo.IBCPortID, res.Ok.Messages, res.Ok.Attributes, res.Ok.Acknowledgement, res.Ok.Events)
}

// OnAckPacket calls the contract to handle the "acknowledgement" data which can contain success or failure of a packet
// acknowledgement written on the receiving chain for example. This is application level data and fully owned by the
// contract. The use of the standard acknowledgement envelope is recommended: https://github.com/cosmos/ics/tree/master/spec/ics-004-channel-and-packet-semantics#acknowledgement-envelope
//
// On application errors the contract can revert an operation like returning tokens as in ibc-transfer.
//
// For more information see: https://github.com/cosmos/ics/tree/master/spec/ics-004-channel-and-packet-semantics#packet-flow--handling
func (k Keeper) OnAckPacket(
	ctx sdk.Context,
	contractAddr sdk.AccAddress,
	msg wasmvmtypes.IBCPacketAckMsg,
) error {
	defer telemetry.MeasureSince(time.Now(), "wasm", "contract", "ibc-ack-packet")

	contractInfo, err := k.GetContractInfo(ctx, contractAddr)
	if err != nil {
		return err
	}

	codeInfo, err := k.GetCodeInfo(ctx, contractInfo.GetCodeID())
	if err != nil {
		return err
	}

	storeKey := types.GetContractStoreKey(contractAddr)
	store := prefix.NewStore(ctx.KVStore(k.storeKey), storeKey)

	env := types.NewEnv(ctx, contractAddr)
	querier := types.NewWasmQuerier()

	gas := k.getWasmVMGasRemaining(ctx)
	res, gasUsed, execErr := k.wasmVM.IBCPacketAck(codeInfo.CodeHash, env, msg, store, k.getCosmWasmAPI(), querier, ctx.GasMeter(), gas, types.JSONDeserializationWasmGasCost)
	k.consumeWasmVMGas(ctx, gasUsed, "ibc packet ack")
	if execErr != nil {
		return sdkerrors.Wrap(types.ErrExecuteFailed, execErr.Error())
	}

	// emitting events, dispatching submessages	are done in handleIBCBasicContractResponse()
	return k.handleIBCBasicContractResponse(ctx, contractAddr, contractInfo.IBCPortID, res)
}

// OnTimeoutPacket calls the contract to let it know the packet was never received on the destination chain within
// the timeout boundaries.
// The contract should handle this on the application level and undo the original operation
func (k Keeper) OnTimeoutPacket(
	ctx sdk.Context,
	contractAddr sdk.AccAddress,
	msg wasmvmtypes.IBCPacketTimeoutMsg,
) error {
	defer telemetry.MeasureSince(time.Now(), "wasm", "contract", "ibc-timeout-packet")

	contractInfo, err := k.GetContractInfo(ctx, contractAddr)
	if err != nil {
		return err
	}

	codeInfo, err := k.GetCodeInfo(ctx, contractInfo.GetCodeID())
	if err != nil {
		return err
	}

	storeKey := types.GetContractStoreKey(contractAddr)
	store := prefix.NewStore(ctx.KVStore(k.storeKey), storeKey)

	env := types.NewEnv(ctx, contractAddr)
	querier := types.NewWasmQuerier()

	gas := k.getWasmVMGasRemaining(ctx)
	res, gasUsed, execErr := k.wasmVM.IBCPacketTimeout(codeInfo.CodeHash, env, msg, store, k.getCosmWasmAPI(), querier, ctx.GasMeter(), gas, types.JSONDeserializationWasmGasCost)
	k.consumeWasmVMGas(ctx, gasUsed, "ibc packet timeout")
	if execErr != nil {
		return sdkerrors.Wrap(types.ErrExecuteFailed, execErr.Error())
	}

	// emitting events, dispatching submessages	are done in handleIBCBasicContractResponse()
	return k.handleIBCBasicContractResponse(ctx, contractAddr, contractInfo.IBCPortID, res)
}

func (k Keeper) handleIBCBasicContractResponse(ctx sdk.Context, addr sdk.AccAddress, id string, res *wasmvmtypes.IBCBasicResponse) error {
	_, err := k.handleIBCContractResponse(ctx, addr, id, res.Messages, res.Attributes, nil, res.Events)
	return err
}

func (k Keeper) handleIBCContractResponse(
	ctx sdk.Context,
	addr sdk.AccAddress,
	id string,
	msgs []wasmvmtypes.SubMsg,
	attrs []wasmvmtypes.EventAttribute,
	data []byte,
	evts wasmvmtypes.Events,
) ([]byte, error) {
	// consume gas for wasm events
	ctx.GasMeter().ConsumeGas(types.EventCosts(attrs, evts), "Event Cost")

	// parse wasm events to sdk events
	events, err := types.ParseEvents(addr, attrs, evts)
	if err != nil {
		return nil, sdkerrors.Wrap(err, "event validation failed")
	}

	// emit events
	ctx.EventManager().EmitEvents(events)

	// dispatch submessages and messages
	respData := data
	if replyData, err := k.dispatchMessages(ctx, addr, id, msgs...); err != nil {
		return nil, sdkerrors.Wrap(err, "dispatch")
	} else if replyData != nil {
		respData = replyData
	}

	return respData, nil
}
