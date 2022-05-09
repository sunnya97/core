package types

import (
	math "math"
	"strings"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"

	channeltypes "github.com/cosmos/ibc-go/v3/modules/core/04-channel/types"
)

const portIDPrefix = "wasm."

// PortIDForContract build port ID from a contract address
func PortIDForContract(addr sdk.AccAddress) string {
	return portIDPrefix + addr.String()
}

// ContractFromPortID extract a contract address from port ID
func ContractFromPortID(portID string) (sdk.AccAddress, error) {
	if !strings.HasPrefix(portID, portIDPrefix) {
		return nil, sdkerrors.Wrapf(ErrInvalid, "without prefix")
	}
	return sdk.AccAddressFromBech32(portID[len(portIDPrefix):])
}

func ValidateChannelParams(channelID string) error {
	// NOTE: for escrow address security only 2^32 channels are allowed to be created
	// Issue: https://github.com/cosmos/cosmos-sdk/issues/7737
	channelSequence, err := channeltypes.ParseChannelSequence(channelID)
	if err != nil {
		return err
	}
	if channelSequence > math.MaxUint32 {
		return sdkerrors.Wrapf(ErrMaxIBCChannels, "channel sequence %d is greater than max allowed transfer channels %d", channelSequence, math.MaxUint32)
	}
	return nil
}
