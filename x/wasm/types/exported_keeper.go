package types

import (
	wasmvmtypes "github.com/CosmWasm/wasmvm/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	capabilitytypes "github.com/cosmos/cosmos-sdk/x/capability/types"
)

// IBCContractKeeper IBC lifecycle event handler
type IBCContractKeeper interface {
	OnOpenChannel(
		ctx sdk.Context,
		contractAddr sdk.AccAddress,
		msg wasmvmtypes.IBCChannelOpenMsg,
	) error
	OnConnectChannel(
		ctx sdk.Context,
		contractAddr sdk.AccAddress,
		msg wasmvmtypes.IBCChannelConnectMsg,
	) error
	OnCloseChannel(
		ctx sdk.Context,
		contractAddr sdk.AccAddress,
		msg wasmvmtypes.IBCChannelCloseMsg,
	) error
	OnRecvPacket(
		ctx sdk.Context,
		contractAddr sdk.AccAddress,
		msg wasmvmtypes.IBCPacketReceiveMsg,
	) ([]byte, error)
	OnAckPacket(
		ctx sdk.Context,
		contractAddr sdk.AccAddress,
		acknowledgement wasmvmtypes.IBCPacketAckMsg,
	) error
	OnTimeoutPacket(
		ctx sdk.Context,
		contractAddr sdk.AccAddress,
		msg wasmvmtypes.IBCPacketTimeoutMsg,
	) error
	// ClaimCapability allows the transfer module to claim a capability
	// that IBC module passes to it
	ClaimCapability(ctx sdk.Context, cap *capabilitytypes.Capability, name string) error
	// AuthenticateCapability wraps the scopedKeeper's AuthenticateCapability function
	AuthenticateCapability(ctx sdk.Context, cap *capabilitytypes.Capability, name string) bool
}
