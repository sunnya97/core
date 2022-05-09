package keeper

import (
	"encoding/json"
	"io/ioutil"
	"testing"

	wasmvmtypes "github.com/CosmWasm/wasmvm/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/crypto"
	"github.com/terra-money/core/x/wasm/types"
)

func TestOnOpenChannel(t *testing.T) {
	input := CreateTestInput(t)
	parentCtx := input.Ctx
	example := SeedNewContractInstance(t, parentCtx, input, "./testdata/ibc_reflect.wasm", `{"reflect_code_id":1}`, nil)
	const myContractGas = 4000

	_, _, randomAddr := keyPubAddr()

	specs := map[string]struct {
		contractAddr sdk.AccAddress
		contractGas  sdk.Gas
		contractErr  error
		expGas       uint64
		expErr       bool
	}{
		"channel open": {
			contractAddr: example.Contract,
		},
		"unknown contract address": {
			contractAddr: randomAddr,
			expErr:       true,
		},
	}
	for name, spec := range specs {
		t.Run(name, func(t *testing.T) {
			myChannel := wasmvmtypes.IBCChannel{Version: "ibc-reflect-v1", Order: wasmvmtypes.Ordered}
			/*
				myMsg := wasmvmtypes.IBCChannelOpenMsg{OpenTry: &wasmvmtypes.IBCOpenTry{Channel: myChannel, CounterpartyVersion: "foo"}}
				m.IBCChannelOpenFn = func(codeID wasmvm.Checksum, env wasmvmtypes.Env, msg wasmvmtypes.IBCChannelOpenMsg, store wasmvm.KVStore, goapi wasmvm.GoAPI, querier wasmvm.Querier, gasMeter wasmvm.GasMeter, gasLimit uint64, deserCost wasmvmtypes.UFraction) (uint64, error) {
					assert.Equal(t, myMsg, msg)
					return spec.contractGas * types.GasMultiplier, spec.contractErr
				}
			*/

			ctx, _ := parentCtx.CacheContext()

			// when
			msg := wasmvmtypes.IBCChannelOpenMsg{
				OpenTry: &wasmvmtypes.IBCOpenTry{
					Channel:             myChannel,
					CounterpartyVersion: "ibc-reflect-v1",
				},
			}
			err := input.WasmKeeper.OnOpenChannel(ctx, spec.contractAddr, msg)

			// then
			if spec.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestOnConnectChannel(t *testing.T) {
	input := CreateTestInput(t)
	parentCtx := input.Ctx
	example := SeedNewContractInstance(t, parentCtx, input, "./testdata/ibc_reflect.wasm", `{"reflect_code_id":1}`, nil)
	const myContractGas = 40
	_, _, randomAddr := keyPubAddr()

	specs := map[string]struct {
		contractAddr sdk.AccAddress
		contractResp *wasmvmtypes.IBCBasicResponse
		contractErr  error
		//overwriteMessenger *wasmtesting.MockMessageHandler
		expContractGas sdk.Gas
		expErr         bool
		expEventTypes  []string
	}{
		"consume contract gas": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas,
			contractResp:   &wasmvmtypes.IBCBasicResponse{},
		},
		/* from wasmd
		"consume gas on error, ignore events + messages": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas,
			contractResp: &wasmvmtypes.IBCBasicResponse{
				Messages:   []wasmvmtypes.SubMsg{{ReplyOn: wasmvmtypes.ReplyNever, Msg: wasmvmtypes.CosmosMsg{Bank: &wasmvmtypes.BankMsg{}}}},
				Attributes: []wasmvmtypes.EventAttribute{{Key: "Foo", Value: "Bar"}},
			},
			expEventTypes: []string{types.EventTypeWasmPrefix, types.EventTypeFromContract, "wasm-ibc"},
			contractErr:   errors.New("test, ignore"),
			expErr:        true,
		},
		*/
		"dispatch contract messages on success": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas,
			contractResp: &wasmvmtypes.IBCBasicResponse{
				Messages: []wasmvmtypes.SubMsg{{ReplyOn: wasmvmtypes.ReplyNever, Msg: wasmvmtypes.CosmosMsg{Bank: &wasmvmtypes.BankMsg{}}}, {ReplyOn: wasmvmtypes.ReplyNever, Msg: wasmvmtypes.CosmosMsg{Custom: json.RawMessage(`{"foo":"bar"}`)}}},
			},
		},
		"emit contract events on success": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas + 10,
			contractResp: &wasmvmtypes.IBCBasicResponse{
				Attributes: []wasmvmtypes.EventAttribute{{Key: "Foo", Value: "Bar"}},
			},
			expEventTypes: []string{types.EventTypeWasmPrefix},
		},
		/* from wasmdd
		"messenger errors returned, events stored": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas + 10,
			contractResp: &wasmvmtypes.IBCBasicResponse{
				Messages:   []wasmvmtypes.SubMsg{{ReplyOn: wasmvmtypes.ReplyNever, Msg: wasmvmtypes.CosmosMsg{Bank: &wasmvmtypes.BankMsg{}}}, {ReplyOn: wasmvmtypes.ReplyNever, Msg: wasmvmtypes.CosmosMsg{Custom: json.RawMessage(`{"foo":"bar"}`)}}},
				Attributes: []wasmvmtypes.EventAttribute{{Key: "Foo", Value: "Bar"}},
			},
			//overwriteMessenger: wasmtesting.NewErroringMessageHandler(),
			expErr:        true,
			expEventTypes: []string{types.EventTypeWasmPrefix},
		},
		*/
		"unknown contract address": {
			contractAddr: randomAddr,
			expErr:       true,
		},
	}
	for name, spec := range specs {
		t.Run(name, func(t *testing.T) {
			myChannel := wasmvmtypes.IBCChannel{Version: "ibc-relfect-v1", Order: wasmvmtypes.Ordered}
			//myMsg := wasmvmtypes.IBCChannelConnectMsg{OpenConfirm: &wasmvmtypes.IBCOpenConfirm{Channel: myChannel}}
			/*
				m.IBCChannelConnectFn = func(codeID wasmvm.Checksum, env wasmvmtypes.Env, msg wasmvmtypes.IBCChannelConnectMsg, store wasmvm.KVStore, goapi wasmvm.GoAPI, querier wasmvm.Querier, gasMeter wasmvm.GasMeter, gasLimit uint64, deserCost wasmvmtypes.UFraction) (*wasmvmtypes.IBCBasicResponse, uint64, error) {
					assert.Equal(t, msg, myMsg)
					return spec.contractResp, myContractGas * types.GasMultiplier, spec.contractErr
				}
			*/

			ctx, _ := parentCtx.CacheContext()
			ctx = ctx.WithEventManager(sdk.NewEventManager())

			before := ctx.GasMeter().GasConsumed()
			/*
				msger, capturedMsgs := wasmtesting.NewCapturingMessageHandler()
				*messenger = *msger
				if spec.overwriteMessenger != nil {
					*messenger = *spec.overwriteMessenger
				}
			*/

			// when
			msg := wasmvmtypes.IBCChannelConnectMsg{
				OpenConfirm: &wasmvmtypes.IBCOpenConfirm{
					Channel: myChannel,
				},
			}
			err := input.WasmKeeper.OnConnectChannel(ctx, spec.contractAddr, msg)

			// then
			if spec.expErr {
				require.Error(t, err)
				//assert.Empty(t, capturedMsgs) // no messages captured on error
				assert.Equal(t, spec.expEventTypes, stripTypes(ctx.EventManager().Events()))
				return
			}
			require.NoError(t, err)
			// verify gas consumed
			const storageCosts = sdk.Gas(2903)
			assert.Equal(t, spec.expContractGas, ctx.GasMeter().GasConsumed()-before-storageCosts)
			// verify msgs dispatcheda
			/*
				require.Len(t, *capturedMsgs, len(spec.contractResp.Messages))
				for i, m := range spec.contractResp.Messages {
					assert.Equal(t, (*capturedMsgs)[i], m.Msg)
				}
			*/
			assert.Equal(t, spec.expEventTypes, stripTypes(ctx.EventManager().Events()))
		})
	}
}

/*
func TestOnCloseChannel(t *testing.T) {
	input := CreateTestInput(t)
	parentCtx := input.Ctx
	example := SeedNewContractInstance(t, parentCtx, input)
	const myContractGas = 40
	_, _, randomAddr := keyPubAddr()

	specs := map[string]struct {
		contractAddr       sdk.AccAddress
		contractResp       *wasmvmtypes.IBCBasicResponse
		contractErr        error
		overwriteMessenger *wasmtesting.MockMessageHandler
		expContractGas     sdk.Gas
		expErr             bool
		expEventTypes      []string
	}{
		"consume contract gas": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas,
			contractResp:   &wasmvmtypes.IBCBasicResponse{},
		},
		"consume gas on error, ignore events + messages": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas,
			contractResp: &wasmvmtypes.IBCBasicResponse{
				Messages:   []wasmvmtypes.SubMsg{{ReplyOn: wasmvmtypes.ReplyNever, Msg: wasmvmtypes.CosmosMsg{Bank: &wasmvmtypes.BankMsg{}}}},
				Attributes: []wasmvmtypes.EventAttribute{{Key: "Foo", Value: "Bar"}},
			},
			contractErr: errors.New("test, ignore"),
			expErr:      true,
		},
		"dispatch contract messages on success": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas,
			contractResp: &wasmvmtypes.IBCBasicResponse{
				Messages: []wasmvmtypes.SubMsg{{ReplyOn: wasmvmtypes.ReplyNever, Msg: wasmvmtypes.CosmosMsg{Bank: &wasmvmtypes.BankMsg{}}}, {ReplyOn: wasmvmtypes.ReplyNever, Msg: wasmvmtypes.CosmosMsg{Custom: json.RawMessage(`{"foo":"bar"}`)}}},
			},
		},
		"emit contract events on success": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas + 10,
			contractResp: &wasmvmtypes.IBCBasicResponse{
				Attributes: []wasmvmtypes.EventAttribute{{Key: "Foo", Value: "Bar"}},
			},
			expEventTypes: []string{types.EventTypeWasmPrefix},
		},
		"messenger errors returned, events stored": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas + 10,
			contractResp: &wasmvmtypes.IBCBasicResponse{
				Messages:   []wasmvmtypes.SubMsg{{ReplyOn: wasmvmtypes.ReplyNever, Msg: wasmvmtypes.CosmosMsg{Bank: &wasmvmtypes.BankMsg{}}}, {ReplyOn: wasmvmtypes.ReplyNever, Msg: wasmvmtypes.CosmosMsg{Custom: json.RawMessage(`{"foo":"bar"}`)}}},
				Attributes: []wasmvmtypes.EventAttribute{{Key: "Foo", Value: "Bar"}},
			},
			overwriteMessenger: wasmtesting.NewErroringMessageHandler(),
			expErr:             true,
			expEventTypes:      []string{types.EventTypeWasmPrefix},
		},
		"unknown contract address": {
			contractAddr: randomAddr,
			expErr:       true,
		},
	}
	for name, spec := range specs {
		t.Run(name, func(t *testing.T) {
			myChannel := wasmvmtypes.IBCChannel{Version: "my test channel"}
			myMsg := wasmvmtypes.IBCChannelCloseMsg{CloseInit: &wasmvmtypes.IBCCloseInit{Channel: myChannel}}
			m.IBCChannelCloseFn = func(codeID wasmvm.Checksum, env wasmvmtypes.Env, msg wasmvmtypes.IBCChannelCloseMsg, store wasmvm.KVStore, goapi wasmvm.GoAPI, querier wasmvm.Querier, gasMeter wasmvm.GasMeter, gasLimit uint64, deserCost wasmvmtypes.UFraction) (*wasmvmtypes.IBCBasicResponse, uint64, error) {
				assert.Equal(t, msg, myMsg)
				return spec.contractResp, myContractGas * types.GasMultiplier, spec.contractErr
			}

			ctx, _ := parentCtx.CacheContext()
			before := ctx.GasMeter().GasConsumed()
			msger, capturedMsgs := wasmtesting.NewCapturingMessageHandler()
			*messenger = *msger

			if spec.overwriteMessenger != nil {
				*messenger = *spec.overwriteMessenger
			}

			// when
			msg := wasmvmtypes.IBCChannelCloseMsg{
				CloseInit: &wasmvmtypes.IBCCloseInit{
					Channel: myChannel,
				},
			}
			err := keepers.WasmKeeper.OnCloseChannel(ctx, spec.contractAddr, msg)

			// then
			if spec.expErr {
				require.Error(t, err)
				assert.Empty(t, capturedMsgs) // no messages captured on error
				assert.Equal(t, spec.expEventTypes, stripTypes(ctx.EventManager().Events()))
				return
			}
			require.NoError(t, err)
			// verify gas consumed
			const storageCosts = sdk.Gas(2903)
			assert.Equal(t, spec.expContractGas, ctx.GasMeter().GasConsumed()-before-storageCosts)
			// verify msgs dispatched
			require.Len(t, *capturedMsgs, len(spec.contractResp.Messages))
			for i, m := range spec.contractResp.Messages {
				assert.Equal(t, (*capturedMsgs)[i], m.Msg)
			}
			assert.Equal(t, spec.expEventTypes, stripTypes(ctx.EventManager().Events()))
		})
	}
}

func TestOnRecvPacket(t *testing.T) {
	var m wasmtesting.MockWasmer
	wasmtesting.MakeIBCInstantiable(&m)
	var messenger = &wasmtesting.MockMessageHandler{}
	parentCtx, keepers := CreateTestInput(t, false, types.DefaultFeatures, WithMessageHandler(messenger))
	example := SeedNewContractInstance(t, parentCtx, keepers, &m)
	const myContractGas = 40
	const storageCosts = sdk.Gas(2903)
	_, _, randomAddr := keyPubAddr()

	specs := map[string]struct {
		contractAddr       sdk.AccAddress
		contractResp       *wasmvmtypes.IBCReceiveResponse
		contractErr        error
		overwriteMessenger *wasmtesting.MockMessageHandler
		mockReplyFn        func(codeID wasmvm.Checksum, env wasmvmtypes.Env, reply wasmvmtypes.Reply, store wasmvm.KVStore, goapi wasmvm.GoAPI, querier wasmvm.Querier, gasMeter wasmvm.GasMeter, gasLimit uint64, deserCost wasmvmtypes.UFraction) (*wasmvmtypes.Response, uint64, error)
		expContractGas     sdk.Gas
		expAck             []byte
		expErr             bool
		expEventTypes      []string
	}{
		"consume contract gas": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas,
			contractResp: &wasmvmtypes.IBCReceiveResponse{
				Acknowledgement: []byte("myAck"),
			},
			expAck: []byte("myAck"),
		},
		"can return empty ack": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas,
			contractResp:   &wasmvmtypes.IBCReceiveResponse{},
		},
		"consume gas on error, ignore events + messages": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas,
			contractResp: &wasmvmtypes.IBCReceiveResponse{
				Acknowledgement: []byte("myAck"),
				Messages:        []wasmvmtypes.SubMsg{{ReplyOn: wasmvmtypes.ReplyNever, Msg: wasmvmtypes.CosmosMsg{Bank: &wasmvmtypes.BankMsg{}}}},
				Attributes:      []wasmvmtypes.EventAttribute{{Key: "Foo", Value: "Bar"}},
			},
			contractErr: errors.New("test, ignore"),
			expErr:      true,
		},
		"dispatch contract messages on success": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas,
			contractResp: &wasmvmtypes.IBCReceiveResponse{
				Acknowledgement: []byte("myAck"),
				Messages:        []wasmvmtypes.SubMsg{{ReplyOn: wasmvmtypes.ReplyNever, Msg: wasmvmtypes.CosmosMsg{Bank: &wasmvmtypes.BankMsg{}}}, {ReplyOn: wasmvmtypes.ReplyNever, Msg: wasmvmtypes.CosmosMsg{Custom: json.RawMessage(`{"foo":"bar"}`)}}},
			},
			expAck: []byte("myAck"),
		},
		"emit contract attributes on success": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas + 10,
			contractResp: &wasmvmtypes.IBCReceiveResponse{
				Acknowledgement: []byte("myAck"),
				Attributes:      []wasmvmtypes.EventAttribute{{Key: "Foo", Value: "Bar"}},
			},
			expEventTypes: []string{types.EventTypeWasmPrefix},
			expAck:        []byte("myAck"),
		},
		"emit contract events on success": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas + 46, // charge or custom event as well
			contractResp: &wasmvmtypes.IBCReceiveResponse{
				Acknowledgement: []byte("myAck"),
				Attributes:      []wasmvmtypes.EventAttribute{{Key: "Foo", Value: "Bar"}},
				Events: []wasmvmtypes.Event{{
					Type: "custom",
					Attributes: []wasmvmtypes.EventAttribute{{
						Key:   "message",
						Value: "to rudi",
					}},
				}},
			},
			expEventTypes: []string{types.EventTypeWasmPrefix, "wasm-custom"},
			expAck:        []byte("myAck"),
		},
		"messenger errors returned, events stored": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas + 10,
			contractResp: &wasmvmtypes.IBCReceiveResponse{
				Acknowledgement: []byte("myAck"),
				Messages:        []wasmvmtypes.SubMsg{{ReplyOn: wasmvmtypes.ReplyNever, Msg: wasmvmtypes.CosmosMsg{Bank: &wasmvmtypes.BankMsg{}}}, {ReplyOn: wasmvmtypes.ReplyNever, Msg: wasmvmtypes.CosmosMsg{Custom: json.RawMessage(`{"foo":"bar"}`)}}},
				Attributes:      []wasmvmtypes.EventAttribute{{Key: "Foo", Value: "Bar"}},
			},
			overwriteMessenger: wasmtesting.NewErroringMessageHandler(),
			expErr:             true,
			expEventTypes:      []string{types.EventTypeWasmPrefix},
		},
		"submessage reply can overwrite ack data": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas + storageCosts,
			contractResp: &wasmvmtypes.IBCReceiveResponse{
				Acknowledgement: []byte("myAck"),
				Messages:        []wasmvmtypes.SubMsg{{ReplyOn: wasmvmtypes.ReplyAlways, Msg: wasmvmtypes.CosmosMsg{Bank: &wasmvmtypes.BankMsg{}}}},
			},
			mockReplyFn: func(codeID wasmvm.Checksum, env wasmvmtypes.Env, reply wasmvmtypes.Reply, store wasmvm.KVStore, goapi wasmvm.GoAPI, querier wasmvm.Querier, gasMeter wasmvm.GasMeter, gasLimit uint64, deserCost wasmvmtypes.UFraction) (*wasmvmtypes.Response, uint64, error) {
				return &wasmvmtypes.Response{Data: []byte("myBetterAck")}, 0, nil
			},
			expAck: []byte("myBetterAck"),
			//expEventTypes: []string{types.EventTypeReply},
			expEventTypes: []string{types.EventTypeWasmPrefix}, // FIXME: original is EventTypeReply but we don't have event type for replies
		},
		"unknown contract address": {
			contractAddr: randomAddr,
			expErr:       true,
		},
	}
	for name, spec := range specs {
		t.Run(name, func(t *testing.T) {
			myPacket := wasmvmtypes.IBCPacket{Data: []byte("my data")}

			m.IBCPacketReceiveFn = func(codeID wasmvm.Checksum, env wasmvmtypes.Env, msg wasmvmtypes.IBCPacketReceiveMsg, store wasmvm.KVStore, goapi wasmvm.GoAPI, querier wasmvm.Querier, gasMeter wasmvm.GasMeter, gasLimit uint64, deserCost wasmvmtypes.UFraction) (*wasmvmtypes.IBCReceiveResult, uint64, error) {
				assert.Equal(t, myPacket, msg.Packet)
				return &wasmvmtypes.IBCReceiveResult{Ok: spec.contractResp}, myContractGas * types.GasMultiplier, spec.contractErr
			}
			if spec.mockReplyFn != nil {
				m.ReplyFn = spec.mockReplyFn
				h, ok := keepers.WasmKeeper.wasmVMResponseHandler.(*DefaultWasmVMContractResponseHandler)
				require.True(t, ok)
				h.md = NewMessageDispatcher(messenger, keepers.WasmKeeper)
			}

			ctx, _ := parentCtx.CacheContext()
			before := ctx.GasMeter().GasConsumed()

			msger, capturedMsgs := wasmtesting.NewCapturingMessageHandler()
			*messenger = *msger

			if spec.overwriteMessenger != nil {
				*messenger = *spec.overwriteMessenger
			}

			// when
			msg := wasmvmtypes.IBCPacketReceiveMsg{Packet: myPacket}
			gotAck, err := keepers.WasmKeeper.OnRecvPacket(ctx, spec.contractAddr, msg)

			// then
			if spec.expErr {
				require.Error(t, err)
				assert.Empty(t, capturedMsgs) // no messages captured on error
				assert.Equal(t, spec.expEventTypes, stripTypes(ctx.EventManager().Events()))
				return
			}
			require.NoError(t, err)
			require.Equal(t, spec.expAck, gotAck)

			// verify gas consumed
			const storageCosts = sdk.Gas(2903)
			assert.Equal(t, spec.expContractGas, ctx.GasMeter().GasConsumed()-before-storageCosts)
			// verify msgs dispatched
			require.Len(t, *capturedMsgs, len(spec.contractResp.Messages))
			for i, m := range spec.contractResp.Messages {
				assert.Equal(t, (*capturedMsgs)[i], m.Msg)
			}
			assert.Equal(t, spec.expEventTypes, stripTypes(ctx.EventManager().Events()))
		})
	}
}

func TestOnAckPacket(t *testing.T) {
	var m wasmtesting.MockWasmer
	wasmtesting.MakeIBCInstantiable(&m)
	var messenger = &wasmtesting.MockMessageHandler{}
	parentCtx, keepers := CreateTestInput(t, false, types.DefaultFeatures, WithMessageHandler(messenger))
	example := SeedNewContractInstance(t, parentCtx, keepers, &m)
	const myContractGas = 40
	_, _, randomAddr := keyPubAddr()

	specs := map[string]struct {
		contractAddr       sdk.AccAddress
		contractResp       *wasmvmtypes.IBCBasicResponse
		contractErr        error
		overwriteMessenger *wasmtesting.MockMessageHandler
		expContractGas     sdk.Gas
		expErr             bool
		expEventTypes      []string
	}{
		"consume contract gas": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas,
			contractResp:   &wasmvmtypes.IBCBasicResponse{},
		},
		"consume gas on error, ignore events + messages": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas,
			contractResp: &wasmvmtypes.IBCBasicResponse{
				Messages:   []wasmvmtypes.SubMsg{{ReplyOn: wasmvmtypes.ReplyNever, Msg: wasmvmtypes.CosmosMsg{Bank: &wasmvmtypes.BankMsg{}}}},
				Attributes: []wasmvmtypes.EventAttribute{{Key: "Foo", Value: "Bar"}},
			},
			contractErr: errors.New("test, ignore"),
			expErr:      true,
		},
		"dispatch contract messages on success": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas,
			contractResp: &wasmvmtypes.IBCBasicResponse{
				Messages: []wasmvmtypes.SubMsg{{ReplyOn: wasmvmtypes.ReplyNever, Msg: wasmvmtypes.CosmosMsg{Bank: &wasmvmtypes.BankMsg{}}}, {ReplyOn: wasmvmtypes.ReplyNever, Msg: wasmvmtypes.CosmosMsg{Custom: json.RawMessage(`{"foo":"bar"}`)}}},
			},
		},
		"emit contract events on success": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas + 10,
			contractResp: &wasmvmtypes.IBCBasicResponse{
				Attributes: []wasmvmtypes.EventAttribute{{Key: "Foo", Value: "Bar"}},
			},
			expEventTypes: []string{types.EventTypeWasmPrefix},
		},
		"messenger errors returned, events stored": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas + 10,
			contractResp: &wasmvmtypes.IBCBasicResponse{
				Messages:   []wasmvmtypes.SubMsg{{ReplyOn: wasmvmtypes.ReplyNever, Msg: wasmvmtypes.CosmosMsg{Bank: &wasmvmtypes.BankMsg{}}}, {ReplyOn: wasmvmtypes.ReplyNever, Msg: wasmvmtypes.CosmosMsg{Custom: json.RawMessage(`{"foo":"bar"}`)}}},
				Attributes: []wasmvmtypes.EventAttribute{{Key: "Foo", Value: "Bar"}},
			},
			overwriteMessenger: wasmtesting.NewErroringMessageHandler(),
			expErr:             true,
			expEventTypes:      []string{types.EventTypeWasmPrefix},
		},
		"unknown contract address": {
			contractAddr: randomAddr,
			expErr:       true,
		},
	}
	for name, spec := range specs {
		t.Run(name, func(t *testing.T) {

			myAck := wasmvmtypes.IBCPacketAckMsg{Acknowledgement: wasmvmtypes.IBCAcknowledgement{Data: []byte("myAck")}}
			m.IBCPacketAckFn = func(codeID wasmvm.Checksum, env wasmvmtypes.Env, msg wasmvmtypes.IBCPacketAckMsg, store wasmvm.KVStore, goapi wasmvm.GoAPI, querier wasmvm.Querier, gasMeter wasmvm.GasMeter, gasLimit uint64, deserCost wasmvmtypes.UFraction) (*wasmvmtypes.IBCBasicResponse, uint64, error) {
				assert.Equal(t, myAck, msg)
				return spec.contractResp, myContractGas * types.GasMultiplier, spec.contractErr
			}

			ctx, _ := parentCtx.CacheContext()
			before := ctx.GasMeter().GasConsumed()
			msger, capturedMsgs := wasmtesting.NewCapturingMessageHandler()
			*messenger = *msger

			if spec.overwriteMessenger != nil {
				*messenger = *spec.overwriteMessenger
			}

			// when
			err := keepers.WasmKeeper.OnAckPacket(ctx, spec.contractAddr, myAck)

			// then

			if spec.expErr {
				require.Error(t, err)
				assert.Empty(t, capturedMsgs) // no messages captured on error
				assert.Equal(t, spec.expEventTypes, stripTypes(ctx.EventManager().Events()))
				return
			}
			require.NoError(t, err)
			// verify gas consumed
			const storageCosts = sdk.Gas(2903)
			assert.Equal(t, spec.expContractGas, ctx.GasMeter().GasConsumed()-before-storageCosts)
			// verify msgs dispatched
			require.Len(t, *capturedMsgs, len(spec.contractResp.Messages))
			for i, m := range spec.contractResp.Messages {
				assert.Equal(t, (*capturedMsgs)[i], m.Msg)
			}
			assert.Equal(t, spec.expEventTypes, stripTypes(ctx.EventManager().Events()))
		})
	}
}

func TestOnTimeoutPacket(t *testing.T) {
	var m wasmtesting.MockWasmer
	wasmtesting.MakeIBCInstantiable(&m)
	var messenger = &wasmtesting.MockMessageHandler{}
	parentCtx, keepers := CreateTestInput(t, false, types.DefaultFeatures, WithMessageHandler(messenger))
	example := SeedNewContractInstance(t, parentCtx, keepers, &m)
	const myContractGas = 40
	_, _, randomAddr := keyPubAddr()

	specs := map[string]struct {
		contractAddr       sdk.AccAddress
		contractResp       *wasmvmtypes.IBCBasicResponse
		contractErr        error
		overwriteMessenger *wasmtesting.MockMessageHandler
		expContractGas     sdk.Gas
		expErr             bool
		expEventTypes      []string
	}{
		"consume contract gas": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas,
			contractResp:   &wasmvmtypes.IBCBasicResponse{},
		},
		"consume gas on error, ignore events + messages": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas,
			contractResp: &wasmvmtypes.IBCBasicResponse{
				Messages:   []wasmvmtypes.SubMsg{{ReplyOn: wasmvmtypes.ReplyNever, Msg: wasmvmtypes.CosmosMsg{Bank: &wasmvmtypes.BankMsg{}}}},
				Attributes: []wasmvmtypes.EventAttribute{{Key: "Foo", Value: "Bar"}},
			},
			contractErr: errors.New("test, ignore"),
			expErr:      true,
		},
		"dispatch contract messages on success": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas,
			contractResp: &wasmvmtypes.IBCBasicResponse{
				Messages: []wasmvmtypes.SubMsg{{ReplyOn: wasmvmtypes.ReplyNever, Msg: wasmvmtypes.CosmosMsg{Bank: &wasmvmtypes.BankMsg{}}}, {ReplyOn: wasmvmtypes.ReplyNever, Msg: wasmvmtypes.CosmosMsg{Custom: json.RawMessage(`{"foo":"bar"}`)}}},
			},
		},
		"emit contract attributes on success": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas + 10,
			contractResp: &wasmvmtypes.IBCBasicResponse{
				Attributes: []wasmvmtypes.EventAttribute{{Key: "Foo", Value: "Bar"}},
			},
			expEventTypes: []string{types.EventTypeWasmPrefix},
		},
		"emit contract events on success": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas + 46, // cost for custom events
			contractResp: &wasmvmtypes.IBCBasicResponse{
				Attributes: []wasmvmtypes.EventAttribute{{Key: "Foo", Value: "Bar"}},
				Events: []wasmvmtypes.Event{{
					Type: "custom",
					Attributes: []wasmvmtypes.EventAttribute{{
						Key:   "message",
						Value: "to rudi",
					}},
				}},
			},
			expEventTypes: []string{types.EventTypeWasmPrefix, "wasm-custom"},
		},
		"messenger errors returned, events stored before": {
			contractAddr:   example.Contract,
			expContractGas: myContractGas + 10,
			contractResp: &wasmvmtypes.IBCBasicResponse{
				Messages:   []wasmvmtypes.SubMsg{{ReplyOn: wasmvmtypes.ReplyNever, Msg: wasmvmtypes.CosmosMsg{Bank: &wasmvmtypes.BankMsg{}}}, {ReplyOn: wasmvmtypes.ReplyNever, Msg: wasmvmtypes.CosmosMsg{Custom: json.RawMessage(`{"foo":"bar"}`)}}},
				Attributes: []wasmvmtypes.EventAttribute{{Key: "Foo", Value: "Bar"}},
			},
			overwriteMessenger: wasmtesting.NewErroringMessageHandler(),
			expErr:             true,
			expEventTypes:      []string{types.EventTypeWasmPrefix},
		},
		"unknown contract address": {
			contractAddr: randomAddr,
			expErr:       true,
		},
	}
	for name, spec := range specs {
		t.Run(name, func(t *testing.T) {
			myPacket := wasmvmtypes.IBCPacket{Data: []byte("my test packet")}
			m.IBCPacketTimeoutFn = func(codeID wasmvm.Checksum, env wasmvmtypes.Env, msg wasmvmtypes.IBCPacketTimeoutMsg, store wasmvm.KVStore, goapi wasmvm.GoAPI, querier wasmvm.Querier, gasMeter wasmvm.GasMeter, gasLimit uint64, deserCost wasmvmtypes.UFraction) (*wasmvmtypes.IBCBasicResponse, uint64, error) {
				assert.Equal(t, myPacket, msg.Packet)
				return spec.contractResp, myContractGas * types.GasMultiplier, spec.contractErr
			}

			ctx, _ := parentCtx.CacheContext()
			before := ctx.GasMeter().GasConsumed()
			msger, capturedMsgs := wasmtesting.NewCapturingMessageHandler()
			*messenger = *msger

			if spec.overwriteMessenger != nil {
				*messenger = *spec.overwriteMessenger
			}

			// when
			msg := wasmvmtypes.IBCPacketTimeoutMsg{Packet: myPacket}
			err := keepers.WasmKeeper.OnTimeoutPacket(ctx, spec.contractAddr, msg)

			// then
			if spec.expErr {
				require.Error(t, err)
				assert.Empty(t, capturedMsgs) // no messages captured on error
				assert.Equal(t, spec.expEventTypes, stripTypes(ctx.EventManager().Events()))
				return
			}
			require.NoError(t, err)
			// verify gas consumed
			const storageCosts = sdk.Gas(2903)
			assert.Equal(t, spec.expContractGas, ctx.GasMeter().GasConsumed()-before-storageCosts)
			// verify msgs dispatched
			require.Len(t, *capturedMsgs, len(spec.contractResp.Messages))
			for i, m := range spec.contractResp.Messages {
				assert.Equal(t, (*capturedMsgs)[i], m.Msg)
			}
			assert.Equal(t, spec.expEventTypes, stripTypes(ctx.EventManager().Events()))
		})
	}
}
*/

func stripTypes(events sdk.Events) []string {
	var r []string
	for _, e := range events {
		r = append(r, e.Type)
	}
	return r
}

type ExampleContract struct {
	InitialAmount sdk.Coins
	Creator       crypto.PrivKey
	CreatorAddr   sdk.AccAddress
	CodeID        uint64
}

type ExampleContractInstance struct {
	ExampleContract
	Contract sdk.AccAddress
}

// SeedNewContractInstance sets the mock wasmerEngine in keeper and calls store + instantiate to init the contract's metadata
func SeedNewContractInstance(t testing.TB, ctx sdk.Context, input TestInput, pathfile, initMsg string, initAmount sdk.Coins) ExampleContractInstance {
	t.Helper()
	exampleContract := StoreRandomContract(t, ctx, input, pathfile)
	contractAddr, _, err := input.WasmKeeper.InstantiateContract(ctx, exampleContract.CodeID, exampleContract.CreatorAddr, exampleContract.CreatorAddr, []byte(initMsg), initAmount)
	require.NoError(t, err)
	return ExampleContractInstance{
		ExampleContract: exampleContract,
		Contract:        contractAddr,
	}
}

var wasmIdent = []byte("\x00\x61\x73\x6D")

// StoreRandomContract sets the mock wasmerEngine in keeper and calls store
func StoreRandomContract(t testing.TB, ctx sdk.Context, input TestInput, pathfile string) ExampleContract {
	t.Helper()
	wasmCode, err := ioutil.ReadFile(pathfile)
	require.NoError(t, err)
	anyAmount := sdk.NewCoins(sdk.NewInt64Coin("denom", 1000))
	creator, _, creatorAddr := keyPubAddr()
	fundAccounts(t, input, creatorAddr, anyAmount)
	codeID, err := input.WasmKeeper.StoreCode(ctx, creatorAddr, wasmCode)
	require.NoError(t, err)
	exampleContract := ExampleContract{InitialAmount: anyAmount, Creator: creator, CreatorAddr: creatorAddr, CodeID: codeID}
	return exampleContract
}

func fundAccounts(t testing.TB, input TestInput, addr sdk.AccAddress, coins sdk.Coins) {
	FundAccount(input, addr, coins)
}

func NewTestFaucet(t testing.TB, ctx sdk.Context, bankKeeper bankkeeper.Keeper, minterModuleName string, initialAmount ...sdk.Coin) *TestFaucet {
	require.NotEmpty(t, initialAmount)
	r := &TestFaucet{t: t, bankKeeper: bankKeeper, minterModuleName: minterModuleName}
	_, _, addr := keyPubAddr()
	r.sender = addr
	r.Mint(ctx, addr, initialAmount...)
	r.balance = initialAmount
	return r
}

type TestFaucet struct {
	t                testing.TB
	bankKeeper       bankkeeper.Keeper
	sender           sdk.AccAddress
	balance          sdk.Coins
	minterModuleName string
}

func (f *TestFaucet) Mint(parentCtx sdk.Context, addr sdk.AccAddress, amounts ...sdk.Coin) {
	require.NotEmpty(f.t, amounts)
	ctx := parentCtx.WithEventManager(sdk.NewEventManager()) // discard all faucet related events
	err := f.bankKeeper.MintCoins(ctx, f.minterModuleName, amounts)
	require.NoError(f.t, err)
	err = f.bankKeeper.SendCoinsFromModuleToAccount(ctx, f.minterModuleName, addr, amounts)
	require.NoError(f.t, err)
	f.balance = f.balance.Add(amounts...)
}

func (f *TestFaucet) Fund(parentCtx sdk.Context, receiver sdk.AccAddress, amounts ...sdk.Coin) {
	require.NotEmpty(f.t, amounts)
	// ensure faucet is always filled
	if !f.balance.IsAllGTE(amounts) {
		f.Mint(parentCtx, f.sender, amounts...)
	}
	ctx := parentCtx.WithEventManager(sdk.NewEventManager()) // discard all faucet related events
	err := f.bankKeeper.SendCoins(ctx, f.sender, receiver, amounts)
	require.NoError(f.t, err)
	f.balance = f.balance.Sub(amounts)
}

func (f *TestFaucet) NewFundedAccount(ctx sdk.Context, amounts ...sdk.Coin) sdk.AccAddress {
	_, _, addr := keyPubAddr()
	f.Fund(ctx, addr, amounts...)
	return addr
}
