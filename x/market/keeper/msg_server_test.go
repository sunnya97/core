package keeper

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	core "github.com/terra-money/core/types"
	"github.com/terra-money/core/x/market/types"
)

func TestMsgServerSwap(t *testing.T) {
	input := CreateTestInput(t)
	impl := NewMsgServerImpl(input.MarketKeeper)

	oracle := input.OracleKeeper
	oracle.SetLunaExchangeRate(input.Ctx, "uusd", sdk.NewDec(50))
	oracle.SetLunaExchangeRate(input.Ctx, "usdr", sdk.NewDec(50))

	deposit := sdk.NewCoins(sdk.NewInt64Coin(core.MicroLunaDenom, 10_000_000))
	offerer := createFakeFundedAccount(input.Ctx, input.AccountKeeper, input.BankKeeper, deposit)

	offer := sdk.NewCoin("uluna", sdk.NewInt(1_000_000))
	msg := types.NewMsgSwap(offerer, offer, "uusd")

	ctx := sdk.WrapSDKContext(input.Ctx)
	resp, err := impl.Swap(ctx, msg)

	require.NoError(t, err)
	require.Equal(t, resp.GetSwapFee(), sdk.NewCoin("uusd", sdk.NewInt(1_000_000)))
	require.Equal(t, resp.GetSwapCoin(), sdk.NewCoin("uusd", sdk.NewInt(49_000_000)))
}

func TestMsgServerSwapSend(t *testing.T) {
	input := CreateTestInput(t)
	impl := NewMsgServerImpl(input.MarketKeeper)

	oracle := input.OracleKeeper
	oracle.SetLunaExchangeRate(input.Ctx, "uusd", sdk.NewDec(50))
	oracle.SetLunaExchangeRate(input.Ctx, "usdr", sdk.NewDec(50))

	deposit := sdk.NewCoins(sdk.NewInt64Coin(core.MicroLunaDenom, 10_000_000))
	offerer := createFakeFundedAccount(input.Ctx, input.AccountKeeper, input.BankKeeper, deposit)

	offer := sdk.NewCoin("uluna", sdk.NewInt(1_000_000))
	recepient := sdk.AccAddress("terra1x46rqay4d3cssq8gxxvqz8xt6nwlz4td20k38v")
	msg := types.NewMsgSwapSend(offerer, recepient, offer, "uusd")

	ctx := sdk.WrapSDKContext(input.Ctx)
	resp, err := impl.SwapSend(ctx, msg)

	require.NoError(t, err)
	require.Equal(t, resp.GetSwapFee(), sdk.NewCoin("uusd", sdk.NewInt(1_000_000)))
	require.Equal(t, resp.GetSwapCoin(), sdk.NewCoin("uusd", sdk.NewInt(49_000_000)))
}
