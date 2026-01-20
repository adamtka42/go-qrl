package legacypool

import (
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

const (
	heavyTxPayloadSize   = 20 * 1024
	defaultSpammersCount = 25
	txPerSpammer         = 60
	unlimitedTestCount   = 10_000_000
)

func printMemUsage(t *testing.T, tag string, loopCounter uint64, realPending, realQueued int) {
	t.Helper()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	activeRAM := m.Alloc / 1024 / 1024
	osReserved := m.Sys / 1024 / 1024

	t.Logf("[%s] Loop: %-6d | MAPS[Pending:%d Queued:%d] | Active RAM: %3d MB | OS Reserved: %3d MB",
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
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	key, err := crypto.GenerateMLDSA87Key()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	address := common.Address(key.GetAddress())

	setupStressPool := func(t *testing.T, config Config) *LegacyPool {
		t.Helper()

		statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		if err != nil {
			t.Fatalf("Failed to create state: %v", err)
		}

		blockchain := newTestBlockChain(params.TestChainConfig, 10000000, statedb, new(event.Feed))
		pool := New(config, blockchain)

		if err := pool.Init(new(big.Int).SetUint64(config.PriceLimit), blockchain.CurrentBlock(), makeAddressReserver()); err != nil {
			t.Fatalf("Failed to init pool: %v", err)
		}
		<-pool.initDoneCh

		testAddBalance(pool, address, big.NewInt(1000000000000000000))
		return pool
	}

	t.Run("DefaultLimits_Pending", func(t *testing.T) {
		config := DefaultConfig
		pool := setupStressPool(t, config)
		defer pool.Close()

		t.Log("--- START: Default Limits (Pending) ---")

		totalTx := config.GlobalSlots * 5
		for i := range totalTx {
			tx := dynamicFeeDataTx(uint64(i), 2000000, big.NewInt(100), big.NewInt(10), key, heavyTxPayloadSize)
			errs := pool.addRemotesSync([]*types.Transaction{tx})

			if len(errs) > 0 && errs[0] != nil {
				if i == 0 {
					t.Fatalf("First TX failed: %v", errs[0])
				}
				// Later errors are expected when pool is full
			}

			if i%500 == 0 {
				realP, realQ := countMapRealSize(pool)
				printMemUsage(t, "Pending", uint64(i), realP, realQ)
			}
		}

		p, q := pool.Stats()
		t.Logf("Final Stats -> Pending: %d, Queued: %d (Expected Pending capped ~%d)", p, q, config.GlobalSlots)

		if p > int(config.GlobalSlots)+int(config.GlobalQueue) {
			t.Errorf("Pool exceeded limits: pending=%d, limit=%d", p, config.GlobalSlots)
		}
	})

	t.Run("DefaultLimits_FullCombo", func(t *testing.T) {
		config := DefaultConfig
		pool := setupStressPool(t, config)
		defer pool.Close()

		t.Log("--- START: Full Combo Stress Test (Multi-Account) ---")
		t.Log(">> Filling Global Pending (using Main Account)...")

		pendingCount := config.GlobalSlots * 2
		for i := range pendingCount {
			tx := transaction(uint64(i), 100000, key)
			pool.addRemotes([]*types.Transaction{tx})

			if i > 0 && i%500 == 0 {
				curP, curQ := pool.Stats()
				realP, realQ := countMapRealSize(pool)
				printMemUsage(t, "PendingFill", uint64(i), realP, realQ)
				t.Logf("  Pool stats: Pending=%d, Queued=%d", curP, curQ)
			}
		}

		t.Logf(">> Adding queued transactions from %d spammer accounts...", defaultSpammersCount)

		for spammerIdx := range defaultSpammersCount {
			spamKey, err := crypto.GenerateMLDSA87Key()
			if err != nil {
				t.Fatalf("Failed to generate spammer key %d: %v", spammerIdx, err)
			}
			spamAddr := spamKey.GetAddress()
			testAddBalance(pool, spamAddr, big.NewInt(1000000000000000000))

			batch := make([]*types.Transaction, 0, txPerSpammer)
			for j := range txPerSpammer {
				tx := transaction(uint64(100+j), 100000, spamKey)
				batch = append(batch, tx)
			}

			pool.addRemotes(batch)

			curP, curQ := pool.Stats()
			totalTxSoFar := pendingCount + uint64((spammerIdx+1)*txPerSpammer)
			realP, realQ := countMapRealSize(pool)
			printMemUsage(t, "QueueFill", totalTxSoFar, realP, realQ)
			t.Logf("  Spammer %d/%d | Pool stats: Pending=%d, Queued=%d", spammerIdx+1, defaultSpammersCount, curP, curQ)
		}

		t.Log(">> Waiting for pool to stabilize...")
		waitForPoolStabilization(t, pool, config, 5*time.Second)

		p, q := pool.Stats()
		t.Logf("Final Stats -> Pending: %d, Queued: %d", p, q)

		runtime.GC()
		realP, realQ := countMapRealSize(pool)
		printMemUsage(t, "FullCombo Final (After GC)", pendingCount+uint64(defaultSpammersCount*txPerSpammer), realP, realQ)

		if p > int(config.GlobalSlots) {
			t.Errorf("Pending exceeded GlobalSlots: got %d, limit %d", p, config.GlobalSlots)
		}
		if q > int(config.GlobalQueue) {
			t.Errorf("Queued exceeded GlobalQueue: got %d, limit %d", q, config.GlobalQueue)
		}
	})

	t.Run("Unlimited_CrashTest", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping unlimited crash test in short mode")
		}

		// This test uses a lot of memory - skip if STRESS_TEST env var is not set
		t.Log("WARNING: This test will consume significant memory!")

		config := DefaultConfig
		config.GlobalSlots = unlimitedTestCount
		config.GlobalQueue = unlimitedTestCount
		config.AccountSlots = unlimitedTestCount
		config.AccountQueue = unlimitedTestCount

		pool := setupStressPool(t, config)
		defer pool.Close()

		t.Log("--- START: Unlimited Memory Stress Test ---")

		runtime.GC()
		printMemUsage(t, "Start", 0, 0, 0)

		for i := range unlimitedTestCount {
			tx := transaction(uint64(i), 100000, key)
			pool.addRemotes([]*types.Transaction{tx})

			if i%5000 == 0 && i > 0 {
				realP, realQ := countMapRealSize(pool)
				printMemUsage(t, "Stress", uint64(i), realP, realQ)
			}
		}

		waitForPoolStabilization(t, pool, config, 5*time.Second)

		p, q := pool.Stats()
		t.Log("Final Memory Usage:")
		realP, realQ := countMapRealSize(pool)
		printMemUsage(t, "Final", unlimitedTestCount, realP, realQ)
		t.Logf("Managed to store -> Pending: %d, Queued: %d", p, q)

		if p == 0 && q == 0 {
			t.Error("No transactions were stored in the pool")
		}
	})
}

func waitForPoolStabilization(t *testing.T, pool *LegacyPool, config Config, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	maxTotal := int(config.GlobalSlots + config.GlobalQueue)

	for time.Now().Before(deadline) {
		p, q := pool.Stats()
		if p+q <= maxTotal {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}
