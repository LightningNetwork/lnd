package chainfee

import (
	"encoding/json"
	"fmt"
	"io"
	prand "math/rand"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcutil"
)

const (
	// maxBlockTarget is the highest number of blocks confirmations that
	// a WebAPIEstimator will cache fees for. This number is chosen
	// because it's the highest number of confs bitcoind will return a fee
	// estimate for.
	maxBlockTarget uint32 = 1008

	// minBlockTarget is the lowest number of blocks confirmations that
	// a WebAPIEstimator will cache fees for. Requesting an estimate for
	// less than this will result in an error.
	minBlockTarget uint32 = 1

	// minFeeUpdateTimeout represents the minimum interval in which a
	// WebAPIEstimator will request fresh fees from its API.
	minFeeUpdateTimeout = 5 * time.Minute

	// maxFeeUpdateTimeout represents the maximum interval in which a
	// WebAPIEstimator will request fresh fees from its API.
	maxFeeUpdateTimeout = 20 * time.Minute
)

// Estimator provides the ability to estimate on-chain transaction fees for
// various combinations of transaction sizes and desired confirmation time
// (measured by number of blocks).
type Estimator interface {
	// EstimateFeePerKW takes in a target for the number of blocks until an
	// initial confirmation and returns the estimated fee expressed in
	// sat/kw.
	EstimateFeePerKW(numBlocks uint32) (SatPerKWeight, error)

	// Start signals the Estimator to start any processes or goroutines
	// it needs to perform its duty.
	Start() error

	// Stop stops any spawned goroutines and cleans up the resources used
	// by the fee estimator.
	Stop() error

	// RelayFeePerKW returns the minimum fee rate required for transactions
	// to be relayed. This is also the basis for calculation of the dust
	// limit.
	RelayFeePerKW() SatPerKWeight
}

// StaticEstimator will return a static value for all fee calculation requests.
// It is designed to be replaced by a proper fee calculation implementation.
// The fees are not accessible directly, because changing them would not be
// thread safe.
type StaticEstimator struct {
	// feePerKW is the static fee rate in satoshis-per-vbyte that will be
	// returned by this fee estimator.
	feePerKW SatPerKWeight

	// relayFee is the minimum fee rate required for transactions to be
	// relayed.
	relayFee SatPerKWeight
}

// NewStaticEstimator returns a new static fee estimator instance.
func NewStaticEstimator(feePerKW, relayFee SatPerKWeight) *StaticEstimator {

	return &StaticEstimator{
		feePerKW: feePerKW,
		relayFee: relayFee,
	}
}

// EstimateFeePerKW will return a static value for fee calculations.
//
// NOTE: This method is part of the Estimator interface.
func (e StaticEstimator) EstimateFeePerKW(numBlocks uint32) (SatPerKWeight, error) {
	return e.feePerKW, nil
}

// RelayFeePerKW returns the minimum fee rate required for transactions to be
// relayed.
//
// NOTE: This method is part of the Estimator interface.
func (e StaticEstimator) RelayFeePerKW() SatPerKWeight {
	return e.relayFee
}

// Start signals the Estimator to start any processes or goroutines
// it needs to perform its duty.
//
// NOTE: This method is part of the Estimator interface.
func (e StaticEstimator) Start() error {
	return nil
}

// Stop stops any spawned goroutines and cleans up the resources used
// by the fee estimator.
//
// NOTE: This method is part of the Estimator interface.
func (e StaticEstimator) Stop() error {
	return nil
}

// A compile-time assertion to ensure that StaticFeeEstimator implements the
// Estimator interface.
var _ Estimator = (*StaticEstimator)(nil)

// BtcdEstimator is an implementation of the Estimator interface backed
// by the RPC interface of an active btcd node. This implementation will proxy
// any fee estimation requests to btcd's RPC interface.
type BtcdEstimator struct {
	// fallbackFeePerKW is the fall back fee rate in sat/kw that is returned
	// if the fee estimator does not yet have enough data to actually
	// produce fee estimates.
	fallbackFeePerKW SatPerKWeight

	// minFeePerKW is the minimum fee, in sat/kw, that we should enforce.
	// This will be used as the default fee rate for a transaction when the
	// estimated fee rate is too low to allow the transaction to propagate
	// through the network.
	minFeePerKW SatPerKWeight

	btcdConn *rpcclient.Client
}

// NewBtcdEstimator creates a new BtcdEstimator given a fully populated
// rpc config that is able to successfully connect and authenticate with the
// btcd node, and also a fall back fee rate. The fallback fee rate is used in
// the occasion that the estimator has insufficient data, or returns zero for a
// fee estimate.
func NewBtcdEstimator(rpcConfig rpcclient.ConnConfig,
	fallBackFeeRate SatPerKWeight) (*BtcdEstimator, error) {

	rpcConfig.DisableConnectOnNew = true
	rpcConfig.DisableAutoReconnect = false
	chainConn, err := rpcclient.New(&rpcConfig, nil)
	if err != nil {
		return nil, err
	}

	return &BtcdEstimator{
		fallbackFeePerKW: fallBackFeeRate,
		btcdConn:         chainConn,
	}, nil
}

// Start signals the Estimator to start any processes or goroutines
// it needs to perform its duty.
//
// NOTE: This method is part of the Estimator interface.
func (b *BtcdEstimator) Start() error {
	if err := b.btcdConn.Connect(20); err != nil {
		return err
	}

	// Once the connection to the backend node has been established, we'll
	// query it for its minimum relay fee.
	info, err := b.btcdConn.GetInfo()
	if err != nil {
		return err
	}

	relayFee, err := btcutil.NewAmount(info.RelayFee)
	if err != nil {
		return err
	}

	// The fee rate is expressed in sat/kb, so we'll manually convert it to
	// our desired sat/kw rate.
	minRelayFeePerKw := SatPerKVByte(relayFee).FeePerKWeight()

	// By default, we'll use the backend node's minimum relay fee as the
	// minimum fee rate we'll propose for transacations. However, if this
	// happens to be lower than our fee floor, we'll enforce that instead.
	b.minFeePerKW = minRelayFeePerKw
	if b.minFeePerKW < FeePerKwFloor {
		b.minFeePerKW = FeePerKwFloor
	}

	log.Debugf("Using minimum fee rate of %v sat/kw",
		int64(b.minFeePerKW))

	return nil
}

// Stop stops any spawned goroutines and cleans up the resources used
// by the fee estimator.
//
// NOTE: This method is part of the Estimator interface.
func (b *BtcdEstimator) Stop() error {
	b.btcdConn.Shutdown()

	return nil
}

// EstimateFeePerKW takes in a target for the number of blocks until an initial
// confirmation and returns the estimated fee expressed in sat/kw.
//
// NOTE: This method is part of the Estimator interface.
func (b *BtcdEstimator) EstimateFeePerKW(numBlocks uint32) (SatPerKWeight, error) {
	feeEstimate, err := b.fetchEstimate(numBlocks)
	switch {
	// If the estimator doesn't have enough data, or returns an error, then
	// to return a proper value, then we'll return the default fall back
	// fee rate.
	case err != nil:
		log.Errorf("unable to query estimator: %v", err)
		fallthrough

	case feeEstimate == 0:
		return b.fallbackFeePerKW, nil
	}

	return feeEstimate, nil
}

// RelayFeePerKW returns the minimum fee rate required for transactions to be
// relayed.
//
// NOTE: This method is part of the Estimator interface.
func (b *BtcdEstimator) RelayFeePerKW() SatPerKWeight {
	return b.minFeePerKW
}

// fetchEstimate returns a fee estimate for a transaction to be confirmed in
// confTarget blocks. The estimate is returned in sat/kw.
func (b *BtcdEstimator) fetchEstimate(confTarget uint32) (SatPerKWeight, error) {
	// First, we'll fetch the estimate for our confirmation target.
	btcPerKB, err := b.btcdConn.EstimateFee(int64(confTarget))
	if err != nil {
		return 0, err
	}

	// Next, we'll convert the returned value to satoshis, as it's
	// currently returned in BTC.
	satPerKB, err := btcutil.NewAmount(btcPerKB)
	if err != nil {
		return 0, err
	}

	// Since we use fee rates in sat/kw internally, we'll convert the
	// estimated fee rate from its sat/kb representation to sat/kw.
	satPerKw := SatPerKVByte(satPerKB).FeePerKWeight()

	// Finally, we'll enforce our fee floor.
	if satPerKw < b.minFeePerKW {
		log.Debugf("Estimated fee rate of %v sat/kw is too low, "+
			"using fee floor of %v sat/kw instead", satPerKw,
			b.minFeePerKW)
		satPerKw = b.minFeePerKW
	}

	log.Debugf("Returning %v sat/kw for conf target of %v",
		int64(satPerKw), confTarget)

	return satPerKw, nil
}

// A compile-time assertion to ensure that BtcdEstimator implements the
// Estimator interface.
var _ Estimator = (*BtcdEstimator)(nil)

// BitcoindEstimator is an implementation of the Estimator interface backed by
// the RPC interface of an active bitcoind node. This implementation will proxy
// any fee estimation requests to bitcoind's RPC interface.
type BitcoindEstimator struct {
	// fallbackFeePerKW is the fallback fee rate in sat/kw that is returned
	// if the fee estimator does not yet have enough data to actually
	// produce fee estimates.
	fallbackFeePerKW SatPerKWeight

	// minFeePerKW is the minimum fee, in sat/kw, that we should enforce.
	// This will be used as the default fee rate for a transaction when the
	// estimated fee rate is too low to allow the transaction to propagate
	// through the network.
	minFeePerKW SatPerKWeight

	// feeMode is the estimate_mode to use when calling "estimatesmartfee".
	// It can be either "ECONOMICAL" or "CONSERVATIVE", and it's default
	// to "CONSERVATIVE".
	feeMode string

	bitcoindConn *rpcclient.Client
}

// NewBitcoindEstimator creates a new BitcoindEstimator given a fully populated
// rpc config that is able to successfully connect and authenticate with the
// bitcoind node, and also a fall back fee rate. The fallback fee rate is used
// in the occasion that the estimator has insufficient data, or returns zero
// for a fee estimate.
func NewBitcoindEstimator(rpcConfig rpcclient.ConnConfig, feeMode string,
	fallBackFeeRate SatPerKWeight) (*BitcoindEstimator, error) {

	rpcConfig.DisableConnectOnNew = true
	rpcConfig.DisableAutoReconnect = false
	rpcConfig.DisableTLS = true
	rpcConfig.HTTPPostMode = true
	chainConn, err := rpcclient.New(&rpcConfig, nil)
	if err != nil {
		return nil, err
	}

	return &BitcoindEstimator{
		fallbackFeePerKW: fallBackFeeRate,
		bitcoindConn:     chainConn,
		feeMode:          feeMode,
	}, nil
}

// Start signals the Estimator to start any processes or goroutines
// it needs to perform its duty.
//
// NOTE: This method is part of the Estimator interface.
func (b *BitcoindEstimator) Start() error {
	// Once the connection to the backend node has been established, we'll
	// query it for its minimum relay fee. Since the `getinfo` RPC has been
	// deprecated for `bitcoind`, we'll need to send a `getnetworkinfo`
	// command as a raw request.
	resp, err := b.bitcoindConn.RawRequest("getnetworkinfo", nil)
	if err != nil {
		return err
	}

	// Parse the response to retrieve the relay fee in sat/KB.
	info := struct {
		RelayFee float64 `json:"relayfee"`
	}{}
	if err := json.Unmarshal(resp, &info); err != nil {
		return err
	}

	relayFee, err := btcutil.NewAmount(info.RelayFee)
	if err != nil {
		return err
	}

	// The fee rate is expressed in sat/kb, so we'll manually convert it to
	// our desired sat/kw rate.
	minRelayFeePerKw := SatPerKVByte(relayFee).FeePerKWeight()

	// By default, we'll use the backend node's minimum relay fee as the
	// minimum fee rate we'll propose for transacations. However, if this
	// happens to be lower than our fee floor, we'll enforce that instead.
	b.minFeePerKW = minRelayFeePerKw
	if b.minFeePerKW < FeePerKwFloor {
		b.minFeePerKW = FeePerKwFloor
	}

	log.Debugf("Using minimum fee rate of %v sat/kw",
		int64(b.minFeePerKW))

	return nil
}

// Stop stops any spawned goroutines and cleans up the resources used
// by the fee estimator.
//
// NOTE: This method is part of the Estimator interface.
func (b *BitcoindEstimator) Stop() error {
	return nil
}

// EstimateFeePerKW takes in a target for the number of blocks until an initial
// confirmation and returns the estimated fee expressed in sat/kw.
//
// NOTE: This method is part of the Estimator interface.
func (b *BitcoindEstimator) EstimateFeePerKW(
	numBlocks uint32) (SatPerKWeight, error) {

	if numBlocks > maxBlockTarget {
		log.Debugf("conf target %d exceeds the max value, "+
			"use %d instead.", numBlocks, maxBlockTarget,
		)
		numBlocks = maxBlockTarget
	}

	feeEstimate, err := b.fetchEstimate(numBlocks)
	switch {
	// If the estimator doesn't have enough data, or returns an error, then
	// to return a proper value, then we'll return the default fall back
	// fee rate.
	case err != nil:
		log.Errorf("unable to query estimator: %v", err)
		fallthrough

	case feeEstimate == 0:
		return b.fallbackFeePerKW, nil
	}

	return feeEstimate, nil
}

// RelayFeePerKW returns the minimum fee rate required for transactions to be
// relayed.
//
// NOTE: This method is part of the Estimator interface.
func (b *BitcoindEstimator) RelayFeePerKW() SatPerKWeight {
	return b.minFeePerKW
}

// fetchEstimate returns a fee estimate for a transaction to be confirmed in
// confTarget blocks. The estimate is returned in sat/kw.
func (b *BitcoindEstimator) fetchEstimate(confTarget uint32) (SatPerKWeight, error) {
	// First, we'll send an "estimatesmartfee" command as a raw request,
	// since it isn't supported by btcd but is available in bitcoind.
	target, err := json.Marshal(uint64(confTarget))
	if err != nil {
		return 0, err
	}

	// The mode must be either ECONOMICAL or CONSERVATIVE.
	mode, err := json.Marshal(b.feeMode)
	if err != nil {
		return 0, err
	}

	resp, err := b.bitcoindConn.RawRequest(
		"estimatesmartfee", []json.RawMessage{target, mode},
	)
	if err != nil {
		return 0, err
	}

	// Next, we'll parse the response to get the BTC per KB.
	feeEstimate := struct {
		FeeRate float64 `json:"feerate"`
	}{}
	err = json.Unmarshal(resp, &feeEstimate)
	if err != nil {
		return 0, err
	}

	// Next, we'll convert the returned value to satoshis, as it's currently
	// returned in BTC.
	satPerKB, err := btcutil.NewAmount(feeEstimate.FeeRate)
	if err != nil {
		return 0, err
	}

	// Since we use fee rates in sat/kw internally, we'll convert the
	// estimated fee rate from its sat/kb representation to sat/kw.
	satPerKw := SatPerKVByte(satPerKB).FeePerKWeight()

	// Finally, we'll enforce our fee floor.
	if satPerKw < b.minFeePerKW {
		log.Debugf("Estimated fee rate of %v sat/kw is too low, "+
			"using fee floor of %v sat/kw instead", satPerKw,
			b.minFeePerKW)

		satPerKw = b.minFeePerKW
	}

	log.Debugf("Returning %v sat/kw for conf target of %v",
		int64(satPerKw), confTarget)

	return satPerKw, nil
}

// A compile-time assertion to ensure that BitcoindEstimator implements the
// Estimator interface.
var _ Estimator = (*BitcoindEstimator)(nil)

// WebAPIFeeSource is an interface allows the WebAPIEstimator to query an
// arbitrary HTTP-based fee estimator. Each new set/network will gain an
// implementation of this interface in order to allow the WebAPIEstimator to
// be fully generic in its logic.
type WebAPIFeeSource interface {
	// GenQueryURL generates the full query URL. The value returned by this
	// method should be able to be used directly as a path for an HTTP GET
	// request.
	GenQueryURL() string

	// ParseResponse attempts to parse the body of the response generated
	// by the above query URL. Typically this will be JSON, but the
	// specifics are left to the WebAPIFeeSource implementation.
	ParseResponse(r io.Reader) (map[uint32]uint32, error)
}

// SparseConfFeeSource is an implementation of the WebAPIFeeSource that utilizes
// a user-specified fee estimation API for Bitcoin. It expects the response
// to be in the JSON format: `fee_by_block_target: { ... }` where the value maps
// block targets to fee estimates (in sat per kilovbyte).
type SparseConfFeeSource struct {
	// URL is the fee estimation API specified by the user.
	URL string
}

// GenQueryURL generates the full query URL. The value returned by this
// method should be able to be used directly as a path for an HTTP GET
// request.
//
// NOTE: Part of the WebAPIFeeSource interface.
func (s SparseConfFeeSource) GenQueryURL() string {
	return s.URL
}

// ParseResponse attempts to parse the body of the response generated by the
// above query URL. Typically this will be JSON, but the specifics are left to
// the WebAPIFeeSource implementation.
//
// NOTE: Part of the WebAPIFeeSource interface.
func (s SparseConfFeeSource) ParseResponse(r io.Reader) (map[uint32]uint32, error) {
	type jsonResp struct {
		FeeByBlockTarget map[uint32]uint32 `json:"fee_by_block_target"`
	}

	resp := jsonResp{
		FeeByBlockTarget: make(map[uint32]uint32),
	}
	jsonReader := json.NewDecoder(r)
	if err := jsonReader.Decode(&resp); err != nil {
		return nil, err
	}

	return resp.FeeByBlockTarget, nil
}

// A compile-time assertion to ensure that SparseConfFeeSource implements the
// WebAPIFeeSource interface.
var _ WebAPIFeeSource = (*SparseConfFeeSource)(nil)

// WebAPIEstimator is an implementation of the Estimator interface that
// queries an HTTP-based fee estimation from an existing web API.
type WebAPIEstimator struct {
	started sync.Once
	stopped sync.Once

	// apiSource is the backing web API source we'll use for our queries.
	apiSource WebAPIFeeSource

	// updateFeeTicker is the ticker responsible for updating the Estimator's
	// fee estimates every time it fires.
	updateFeeTicker *time.Ticker

	// feeByBlockTarget is our cache for fees pulled from the API. When a
	// fee estimate request comes in, we pull the estimate from this array
	// rather than re-querying the API, to prevent an inadvertent DoS attack.
	feesMtx          sync.Mutex
	feeByBlockTarget map[uint32]uint32

	// noCache determines whether the web estimator should cache fee
	// estimates.
	noCache bool

	quit chan struct{}
	wg   sync.WaitGroup
}

// NewWebAPIEstimator creates a new WebAPIEstimator from a given URL and a
// fallback default fee. The fees are updated whenever a new block is mined.
func NewWebAPIEstimator(api WebAPIFeeSource, noCache bool) *WebAPIEstimator {
	return &WebAPIEstimator{
		apiSource:        api,
		feeByBlockTarget: make(map[uint32]uint32),
		noCache:          noCache,
		quit:             make(chan struct{}),
	}
}

// EstimateFeePerKW takes in a target for the number of blocks until an initial
// confirmation and returns the estimated fee expressed in sat/kw.
//
// NOTE: This method is part of the Estimator interface.
func (w *WebAPIEstimator) EstimateFeePerKW(numBlocks uint32) (SatPerKWeight, error) {
	if numBlocks > maxBlockTarget {
		numBlocks = maxBlockTarget
	} else if numBlocks < minBlockTarget {
		return 0, fmt.Errorf("conf target of %v is too low, minimum "+
			"accepted is %v", numBlocks, minBlockTarget)
	}

	// Get fee estimates now if we don't refresh periodically.
	if w.noCache {
		w.updateFeeEstimates()
	}

	feePerKb, err := w.getCachedFee(numBlocks)
	if err != nil {
		return 0, err
	}

	// If the result is too low, then we'll clamp it to our current fee
	// floor.
	satPerKw := SatPerKVByte(feePerKb).FeePerKWeight()
	if satPerKw < FeePerKwFloor {
		satPerKw = FeePerKwFloor
	}

	log.Debugf("Web API returning %v sat/kw for conf target of %v",
		int64(satPerKw), numBlocks)

	return satPerKw, nil
}

// Start signals the Estimator to start any processes or goroutines it needs
// to perform its duty.
//
// NOTE: This method is part of the Estimator interface.
func (w *WebAPIEstimator) Start() error {
	// No update loop is needed when we don't cache.
	if w.noCache {
		return nil
	}

	var err error
	w.started.Do(func() {
		log.Infof("Starting web API fee estimator")

		w.updateFeeTicker = time.NewTicker(w.randomFeeUpdateTimeout())
		w.updateFeeEstimates()

		w.wg.Add(1)
		go w.feeUpdateManager()

	})
	return err
}

// Stop stops any spawned goroutines and cleans up the resources used by the
// fee estimator.
//
// NOTE: This method is part of the Estimator interface.
func (w *WebAPIEstimator) Stop() error {
	// Update loop is not running when we don't cache.
	if w.noCache {
		return nil
	}

	w.stopped.Do(func() {
		log.Infof("Stopping web API fee estimator")

		w.updateFeeTicker.Stop()

		close(w.quit)
		w.wg.Wait()
	})
	return nil
}

// RelayFeePerKW returns the minimum fee rate required for transactions to be
// relayed.
//
// NOTE: This method is part of the Estimator interface.
func (w *WebAPIEstimator) RelayFeePerKW() SatPerKWeight {
	return FeePerKwFloor
}

// randomFeeUpdateTimeout returns a random timeout between minFeeUpdateTimeout
// and maxFeeUpdateTimeout that will be used to determine how often the Estimator
// should retrieve fresh fees from its API.
func (w *WebAPIEstimator) randomFeeUpdateTimeout() time.Duration {
	lower := int64(minFeeUpdateTimeout)
	upper := int64(maxFeeUpdateTimeout)
	return time.Duration(prand.Int63n(upper-lower) + lower)
}

// getCachedFee takes in a target for the number of blocks until an initial
// confirmation and returns an estimated fee (if one was returned by the API). If
// the fee was not previously cached, we cache it here.
func (w *WebAPIEstimator) getCachedFee(numBlocks uint32) (uint32, error) {
	w.feesMtx.Lock()
	defer w.feesMtx.Unlock()

	// Search our cached fees for the desired block target. If the target is
	// not cached, then attempt to extrapolate it from the next lowest target
	// that *is* cached. If we successfully extrapolate, then cache the
	// target's fee.
	for target := numBlocks; target >= minBlockTarget; target-- {
		fee, ok := w.feeByBlockTarget[target]
		if !ok {
			continue
		}

		_, ok = w.feeByBlockTarget[numBlocks]
		if !ok {
			w.feeByBlockTarget[numBlocks] = fee
		}
		return fee, nil
	}
	return 0, fmt.Errorf("web API does not include a fee estimation for "+
		"block target of %v", numBlocks)
}

// updateFeeEstimates re-queries the API for fresh fees and caches them.
func (w *WebAPIEstimator) updateFeeEstimates() {
	// Rather than use the default http.Client, we'll make a custom one
	// which will allow us to control how long we'll wait to read the
	// response from the service. This way, if the service is down or
	// overloaded, we can exit early and use our default fee.
	netTransport := &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	netClient := &http.Client{
		Timeout:   time.Second * 10,
		Transport: netTransport,
	}

	// With the client created, we'll query the API source to fetch the URL
	// that we should use to query for the fee estimation.
	targetURL := w.apiSource.GenQueryURL()
	resp, err := netClient.Get(targetURL)
	if err != nil {
		log.Errorf("unable to query web api for fee response: %v",
			err)
		return
	}
	defer resp.Body.Close()

	// Once we've obtained the response, we'll instruct the WebAPIFeeSource
	// to parse out the body to obtain our final result.
	feesByBlockTarget, err := w.apiSource.ParseResponse(resp.Body)
	if err != nil {
		log.Errorf("unable to query web api for fee response: %v",
			err)
		return
	}

	w.feesMtx.Lock()
	w.feeByBlockTarget = feesByBlockTarget
	w.feesMtx.Unlock()
}

// feeUpdateManager updates the fee estimates whenever a new block comes in.
func (w *WebAPIEstimator) feeUpdateManager() {
	defer w.wg.Done()

	for {
		select {
		case <-w.updateFeeTicker.C:
			w.updateFeeEstimates()
		case <-w.quit:
			return
		}
	}
}

// A compile-time assertion to ensure that WebAPIEstimator implements the
// Estimator interface.
var _ Estimator = (*WebAPIEstimator)(nil)

// minRelayFeeManager is used to store and update the minimum relay fee that is
// required by a transaction to be accepted to the mempool.
// The minRelayFeeManager ensures that the backend used to fetch the fee is not
// queried too regularly.
type minRelayFeeManager struct {
	mu                sync.Mutex
	minFeePerKW       SatPerKWeight
	lastUpdatedTime   time.Time
	minUpdateInterval time.Duration
	fetchNewFee       func() (SatPerKWeight, error)
}

// initMinRelayFee is used to set the minFeePerKW of the minRelayFeeManager
// and it requires that the call the the backend succeeds. This is just
// required when the minRelayFeeManager is being initialized.
func (m *minRelayFeeManager) initMinRelayFee() error {
	newMinFee, err := m.fetchNewFee()
	if err != nil {
		return err
	}

	m.minFeePerKW = newMinFee
	m.lastUpdatedTime = time.Now()
	return nil
}

// getFee returns the stored minFeePerKW if it has been updated recently or
// if the call the the chain backend fails. Otherwise, it sets the stored
// minFeePerKW to the fee returned from the backend and floors it based on
// our fee floor.
func (m *minRelayFeeManager) getFee() SatPerKWeight {
	m.mu.Lock()
	defer m.mu.Unlock()

	if time.Since(m.lastUpdatedTime) < m.minUpdateInterval {
		return m.minFeePerKW
	}

	newMinFee, err := m.fetchNewFee()
	if err != nil {
		log.Errorf("unable to fetch updated relay fee chain " +
			"backend. Using last known relay fee instead")

		return m.minFeePerKW
	}

	// By default, we'll use the backend node's minimum relay fee as the
	// minimum fee rate we'll propose for transactions. However, if this
	// happens to be lower than our fee floor, we'll enforce that instead.
	m.minFeePerKW = newMinFee
	if m.minFeePerKW < FeePerKwFloor {
		m.minFeePerKW = FeePerKwFloor
	}
	m.lastUpdatedTime = time.Now()

	log.Debugf("Using minimum fee rate of %v sat/kw",
		int64(m.minFeePerKW))

	return m.minFeePerKW
}
