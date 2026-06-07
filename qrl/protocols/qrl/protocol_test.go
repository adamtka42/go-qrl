// Copyright 2020 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package qrl

import (
	"bytes"
	"math/big"
	"reflect"
	"testing"

	"github.com/theQRL/go-qrl/common"
	"github.com/theQRL/go-qrl/core/types"
	"github.com/theQRL/go-qrl/crypto"
	"github.com/theQRL/go-qrl/crypto/pqcrypto"
	"github.com/theQRL/go-qrl/rlp"
)

// Tests that the custom union field encoder and decoder works correctly.
func TestGetBlockHeadersDataEncodeDecode(t *testing.T) {
	// Create a "random" hash for testing
	var hash common.Hash
	for i := range hash {
		hash[i] = byte(i)
	}
	// Assemble some table driven tests
	tests := []struct {
		packet *GetBlockHeadersRequest
		fail   bool
	}{
		// Providing the origin as either a hash or a number should both work
		{fail: false, packet: &GetBlockHeadersRequest{Origin: HashOrNumber{Number: 314}}},
		{fail: false, packet: &GetBlockHeadersRequest{Origin: HashOrNumber{Hash: hash}}},

		// Providing arbitrary query field should also work
		{fail: false, packet: &GetBlockHeadersRequest{Origin: HashOrNumber{Number: 314}, Amount: 314, Skip: 1, Reverse: true}},
		{fail: false, packet: &GetBlockHeadersRequest{Origin: HashOrNumber{Hash: hash}, Amount: 314, Skip: 1, Reverse: true}},

		// Providing both the origin hash and origin number must fail
		{fail: true, packet: &GetBlockHeadersRequest{Origin: HashOrNumber{Hash: hash, Number: 314}}},
	}
	// Iterate over each of the tests and try to encode and then decode
	for i, tt := range tests {
		bytes, err := rlp.EncodeToBytes(tt.packet)
		if err != nil && !tt.fail {
			t.Fatalf("test %d: failed to encode packet: %v", i, err)
		} else if err == nil && tt.fail {
			t.Fatalf("test %d: encode should have failed", i)
		}
		if !tt.fail {
			packet := new(GetBlockHeadersRequest)
			if err := rlp.DecodeBytes(bytes, packet); err != nil {
				t.Fatalf("test %d: failed to decode packet: %v", i, err)
			}
			if packet.Origin.Hash != tt.packet.Origin.Hash || packet.Origin.Number != tt.packet.Origin.Number || packet.Amount != tt.packet.Amount ||
				packet.Skip != tt.packet.Skip || packet.Reverse != tt.packet.Reverse {
				t.Fatalf("test %d: encode decode mismatch: have %+v, want %+v", i, packet, tt.packet)
			}
		}
	}
}

// TestEmptyMessages tests encoding of empty messages.
func TestEmptyMessages(t *testing.T) {
	// All empty messages encodes to the same format
	want := common.FromHex("c4820457c0")

	for i, msg := range []any{
		// Headers
		GetBlockHeadersPacket{1111, nil},
		BlockHeadersPacket{1111, nil},
		// Bodies
		GetBlockBodiesPacket{1111, nil},
		BlockBodiesPacket{1111, nil},
		BlockBodiesRLPPacket{1111, nil},
		// Receipts
		GetReceiptsPacket{1111, nil},
		ReceiptsPacket{1111, nil},
		// Transactions
		GetPooledTransactionsPacket{1111, nil},
		PooledTransactionsPacket{1111, nil},
		PooledTransactionsRLPPacket{1111, nil},

		// Headers
		BlockHeadersPacket{1111, BlockHeadersRequest([]*types.Header{})},
		// Bodies
		GetBlockBodiesPacket{1111, GetBlockBodiesRequest([]common.Hash{})},
		BlockBodiesPacket{1111, BlockBodiesResponse([]*BlockBody{})},
		BlockBodiesRLPPacket{1111, BlockBodiesRLPResponse([]rlp.RawValue{})},
		// Receipts
		GetReceiptsPacket{1111, GetReceiptsRequest([]common.Hash{})},
		ReceiptsPacket{1111, ReceiptsResponse([][]*types.Receipt{})},
		// Transactions
		GetPooledTransactionsPacket{1111, GetPooledTransactionsRequest([]common.Hash{})},
		PooledTransactionsPacket{1111, PooledTransactionsResponse([]*types.Transaction{})},
		PooledTransactionsRLPPacket{1111, PooledTransactionsRLPResponse([]rlp.RawValue{})},
	} {
		if have, _ := rlp.EncodeToBytes(msg); !bytes.Equal(have, want) {
			t.Errorf("test %d, type %T, have\n\t%x\nwant\n\t%x", i, msg, have, want)
		}
	}
}

// TestMessages tests the encoding of all messages.
func TestMessages(t *testing.T) {
	withdrawalsHash := types.EmptyWithdrawalsHash
	header := &types.Header{
		Number:          big.NewInt(3333),
		GasLimit:        4444,
		GasUsed:         5555,
		Time:            6666,
		Extra:           []byte{0x77, 0x88},
		WithdrawalsHash: &withdrawalsHash,
	}

	signer := types.NewZondSigner(big.NewInt(1))
	to := common.BytesToAddress([]byte{0xb9, 0x4f, 0x53, 0x74})
	var txs []*types.Transaction
	var txRlps []rlp.RawValue
	for i, nonce := range []uint64{3, 5} {
		tx := types.NewTx(&types.DynamicFeeTx{
			ChainID:   big.NewInt(1),
			Nonce:     nonce,
			GasTipCap: big.NewInt(1),
			GasFeeCap: big.NewInt(3),
			Gas:       0x5208,
			To:        &to,
			Value:     big.NewInt(10),
			Data:      []byte{0x55, 0x44},
		})
		tx = mustWithProtocolTestAuth(t, tx, signer, byte(i+1))
		txs = append(txs, tx)

		raw, err := rlp.EncodeToBytes(tx)
		if err != nil {
			t.Fatal(err)
		}
		txRlps = append(txRlps, raw)
	}

	blockBody := &BlockBody{Transactions: txs}
	blockBodyRlp, err := rlp.EncodeToBytes(blockBody)
	if err != nil {
		t.Fatal(err)
	}

	hashes := []common.Hash{
		common.HexToHash("deadc0de"),
		common.HexToHash("feedbeef"),
	}
	receipts := []*types.Receipt{
		{
			Type:              types.DynamicFeeTxType,
			Status:            types.ReceiptStatusFailed,
			CumulativeGasUsed: 1,
			Logs: []*types.Log{
				{
					Address: common.BytesToAddress([]byte{0x11}),
					Topics:  []common.LogTopic{common.HexToLogTopic("dead"), common.HexToLogTopic("beef")},
					Data:    []byte{0x01, 0x00, 0xff},
				},
			},
			TxHash:          hashes[0],
			ContractAddress: common.BytesToAddress([]byte{0x01, 0x11, 0x11}),
			GasUsed:         111111,
		},
	}
	for i, tc := range []struct {
		message  any
		wantHash common.Hash
		wantSize int
	}{
		{
			message:  GetBlockHeadersPacket{1111, &GetBlockHeadersRequest{HashOrNumber{hashes[0], 0}, 5, 5, false}},
			wantHash: common.HexToHash("0xdd8dfb3270bf114aa1f93f44264fda0b55df4c635b15c54446a714f8513c698d"),
			wantSize: 41,
		},
		{
			message:  GetBlockHeadersPacket{1111, &GetBlockHeadersRequest{HashOrNumber{common.Hash{}, 9999}, 5, 5, false}},
			wantHash: common.HexToHash("0xcc9d1a161cf458234015e6a1b009c4406391e51a961f6badcf7f88ab1050ca8b"),
			wantSize: 11,
		},
		{
			message:  BlockHeadersPacket{1111, BlockHeadersRequest{header}},
			wantHash: common.HexToHash("0x0eee5601f9c4633f34b489deeea37de748214395b97ee4ed61d74fcc4aa7c2a2"),
			wantSize: 551,
		},
		{
			message:  GetBlockBodiesPacket{1111, GetBlockBodiesRequest(hashes)},
			wantHash: common.HexToHash("0x968dc0f233147c30ef2cc5aba5510cfc23ee0ab8c46c36abc23044a3825f6232"),
			wantSize: 73,
		},
		{
			message:  BlockBodiesPacket{1111, BlockBodiesResponse([]*BlockBody{blockBody})},
			wantHash: common.HexToHash("0x3004d92516b8252a2ef25255b9b47c1660f3bd8d70330d6b018dfc7cfa072775"),
			wantSize: 14645,
		},
		{
			message:  BlockBodiesRLPPacket{1111, BlockBodiesRLPResponse([]rlp.RawValue{blockBodyRlp})},
			wantHash: common.HexToHash("0x3004d92516b8252a2ef25255b9b47c1660f3bd8d70330d6b018dfc7cfa072775"),
			wantSize: 14645,
		},
		{
			message:  GetReceiptsPacket{1111, GetReceiptsRequest(hashes)},
			wantHash: common.HexToHash("0x968dc0f233147c30ef2cc5aba5510cfc23ee0ab8c46c36abc23044a3825f6232"),
			wantSize: 73,
		},
		{
			message:  ReceiptsPacket{1111, ReceiptsResponse([][]*types.Receipt{receipts})},
			wantHash: common.HexToHash("0x09ddd905239949a702aac3b2ccf606f6fdf8917feb0a022380059ed1c4b3e9f0"),
			wantSize: 488,
		},
		{
			message:  GetPooledTransactionsPacket{1111, GetPooledTransactionsRequest(hashes)},
			wantHash: common.HexToHash("0x968dc0f233147c30ef2cc5aba5510cfc23ee0ab8c46c36abc23044a3825f6232"),
			wantSize: 73,
		},
		{
			message:  PooledTransactionsPacket{1111, PooledTransactionsResponse(txs)},
			wantHash: common.HexToHash("0x56799be5fd805a5717e5c3b21912cf97512a6f87a1e5f84471b0b0dcc499f126"),
			wantSize: 14639,
		},
		{
			message:  PooledTransactionsRLPPacket{1111, PooledTransactionsRLPResponse(txRlps)},
			wantHash: common.HexToHash("0x56799be5fd805a5717e5c3b21912cf97512a6f87a1e5f84471b0b0dcc499f126"),
			wantSize: 14639,
		},
	} {
		have, err := rlp.EncodeToBytes(tc.message)
		if err != nil {
			t.Errorf("test %d, type %T: encode error: %v", i, tc.message, err)
			continue
		}
		if got := crypto.Keccak256Hash(have); got != tc.wantHash {
			t.Errorf("test %d, type %T: RLP hash mismatch\n have: %s (len %d)\n want: %s (len %d)", i, tc.message, got, len(have), tc.wantHash, tc.wantSize)
		}
		if len(have) != tc.wantSize {
			t.Errorf("test %d, type %T: RLP length mismatch: have %d, want %d", i, tc.message, len(have), tc.wantSize)
		}

		roundTrip := reflect.New(reflect.TypeOf(tc.message)).Interface()
		if err := rlp.DecodeBytes(have, roundTrip); err != nil {
			t.Errorf("test %d, type %T: decode error: %v", i, tc.message, err)
			continue
		}
		got := reflect.ValueOf(roundTrip).Elem().Interface()
		if reEncoded, err := rlp.EncodeToBytes(got); err != nil {
			t.Errorf("test %d, type %T: re-encode error: %v", i, tc.message, err)
		} else if !bytes.Equal(reEncoded, have) {
			t.Errorf("test %d, type %T: round-trip mismatch\n have: %x\n want: %x", i, tc.message, reEncoded, have)
		}
	}
}

func mustWithProtocolTestAuth(t *testing.T, tx *types.Transaction, signer types.Signer, seed byte) *types.Transaction {
	t.Helper()

	signature := bytes.Repeat([]byte{seed}, pqcrypto.MLDSA87SignatureLength)
	publicKey := bytes.Repeat([]byte{seed + 0x10}, pqcrypto.MLDSA87PublicKeyLength)
	descriptor := []byte{0x01, 0x00, 0x00}
	extraParams := []byte{seed + 0x20}

	signed, err := tx.WithAuthValues(signer, signature, publicKey, descriptor, extraParams)
	if err != nil {
		t.Fatalf("attach deterministic auth values: %v", err)
	}
	return signed
}
