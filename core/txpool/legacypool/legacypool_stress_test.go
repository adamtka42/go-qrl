package legacypool

import (
	crand "crypto/rand"
	"fmt"
	"math/big"
	"runtime"
	"testing"
	"time"

	"github.com/theQRL/go-zond/common"
	"github.com/theQRL/go-zond/core/rawdb"
	"github.com/theQRL/go-zond/core/state"
	"github.com/theQRL/go-zond/core/types"
	"github.com/theQRL/go-zond/crypto"
	"github.com/theQRL/go-zond/event"
	"github.com/theQRL/go-zond/params"
)

func printMemUsage(tag string, loopCounter uint64, realPending, realQueued int) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	activeRAM := m.Alloc / 1024 / 1024
	osReserved := m.Sys / 1024 / 1024

	fmt.Printf("[%s] Loop: %-6d | MAPS[Pending:%d Queued:%d] | Active RAM: %3d MB | OS Reserved: %3d MB\n",
		tag, loopCounter, realPending, realQueued, activeRAM, osReserved)
}

func countMapRealSize(pool *LegacyPool) (int, int) {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	realPendingCount := 0
	for _, txList := range pool.pending {
		realPendingCount += txList.Len()
	}

	realQueuedCount := 0
	for _, txList := range pool.queue {
		realQueuedCount += txList.Len()
	}

	return realPendingCount, realQueuedCount
}

func TestTxPoolStress(t *testing.T) {
	key, _ := crypto.GenerateMLDSA87Key()
	address := common.Address(key.GetAddress())
	chainConfig := params.TestChainConfig

	setupStressPool := func(config Config) *LegacyPool {
		statedb, _ := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)

		blockchain := newTestBlockChain(params.TestChainConfig, 10000000, statedb, new(event.Feed))

		pool := New(config, blockchain)

		if err := pool.Init(new(big.Int).SetUint64(config.PriceLimit), blockchain.CurrentBlock(), makeAddressReserver()); err != nil {
			panic(err)
		}
		<-pool.initDoneCh

		testAddBalance(pool, address, big.NewInt(1000000000000000000))

		return pool
	}

	createHeavyTx := func(nonce uint64) *types.Transaction {
		payloadSize := 20 * 1024
		data := make([]byte, payloadSize)
		_, err := crand.Read(data)
		if err != nil {
			panic(err)
		}

		txData := &types.DynamicFeeTx{
			ChainID:   params.TestChainConfig.ChainID,
			Nonce:     nonce,
			GasTipCap: big.NewInt(10),
			GasFeeCap: big.NewInt(100),
			Gas:       2000000,
			To:        &address,
			Value:     big.NewInt(1),
			Data:      data,
		}

		tx := types.NewTx(txData)

		signer := types.LatestSigner(chainConfig)
		signedTx, _ := types.SignTx(tx, signer, key)

		return signedTx
	}

	t.Run("DefaultLimits_Pending", func(t *testing.T) {
		config := DefaultConfig
		pool := setupStressPool(config)
		defer pool.Close()

		fmt.Printf("\n--- START: Default Limits (Pending) ---\n")

		for i := range config.GlobalSlots * 5 {
			tx := createHeavyTx(uint64(i))
			errs := pool.addRemotesSync([]*types.Transaction{tx})

			if i == 0 && len(errs) > 0 && errs[0] != nil {
				t.Fatalf("ERROR TX: %v", errs[0])
			}

			if i%500 == 0 {
				realP, realQ := countMapRealSize(pool)
				printMemUsage("Pending", i, realP, realQ)
			}
		}

		p, q := pool.Stats()
		fmt.Printf("Final Stats -> Pending: %d, Queued: %d (Expected Pending capped ~5120)\n", p, q)
	})

	t.Run("DefaultLimits_FullCombo", func(t *testing.T) {
		config := DefaultConfig
		pool := setupStressPool(config)
		defer pool.Close()

		fmt.Printf("\n--- START: Full Combo Stress Test (Multi-Account) ---\n")
		fmt.Println(">> Filling Global Pending (using Main Account)...")

		pendingCount := config.GlobalSlots * 2
		for i := range config.GlobalSlots * 2 {
			tx := transaction(uint64(i), 100000, key)
			pool.addRemotes([]*types.Transaction{tx})

			if i > 0 && i%500 == 0 {
				curP, curQ := pool.Stats()
				tag := fmt.Sprintf("PendingFill %d | Pool[P:%d Q:%d]", i, curP, curQ)
				realP, realQ := countMapRealSize(pool)
				printMemUsage(tag, i, realP, realQ)
			}
		}

		spammersCount := 25
		txPerSpammer := 60

		for s := range spammersCount {
			spamKey, _ := crypto.GenerateMLDSA87Key()
			spamAddr := spamKey.GetAddress()
			testAddBalance(pool, spamAddr, big.NewInt(1000000000000000000))

			batch := []*types.Transaction{}
			for j := range txPerSpammer {
				tx := transaction(uint64(100+j), 100000, spamKey)
				batch = append(batch, tx)
			}

			pool.addRemotes(batch)

			curP, curQ := pool.Stats()
			totalTxSoFar := pendingCount + uint64((s+1)*txPerSpammer)
			tag := fmt.Sprintf("QueueFill %d/%d | Pool[P:%d Q:%d]", s+1, spammersCount, curP, curQ)
			realP, realQ := countMapRealSize(pool)
			printMemUsage(tag, uint64(totalTxSoFar), realP, realQ)
		}

		fmt.Println(">> Waiting for pool to stabilize...")
		time.Sleep(3 * time.Second)

		p, q := pool.Stats()
		fmt.Printf("\nFinal Stats -> Pending: %d, Queued: %d\n", p, q)

		runtime.GC()
		realP, realQ := countMapRealSize(pool)
		printMemUsage("FullCombo Final (After GC)", pendingCount+uint64(spammersCount*txPerSpammer), realP, realQ)
	})

	t.Run("Unlimited_CrashTest", func(t *testing.T) {
		config := DefaultConfig
		config.GlobalSlots = 10_000_000
		config.GlobalQueue = 10_000_000
		config.AccountSlots = 10_000_000
		config.AccountQueue = 10_000_000

		pool := setupStressPool(config)
		defer pool.Close()

		fmt.Printf("\n--- START: Unlimited Memory Stress Test ---\n")

		count := 10_000_000

		runtime.GC()
		printMemUsage("Start", 0, 0, 0)

		for i := range count {
			tx := transaction(uint64(i), 100000, key)

			pool.addRemotes([]*types.Transaction{tx})

			if i%5000 == 0 && i > 0 {
				realP, realQ := countMapRealSize(pool)
				printMemUsage("Stress", uint64(i), realP, realQ)
			}
		}

		time.Sleep(2 * time.Second)

		p, q := pool.Stats()
		fmt.Printf("Final Memory Usage:\n")
		realP, realQ := countMapRealSize(pool)
		printMemUsage("Final", uint64(count), realP, realQ)
		fmt.Printf("Managed to store -> Pending: %d, Queued: %d\n", p, q)
	})
}
