// +build rpctest

package itest

var allTestCases = []*testCase{
	{
		name: "test multi-hop htlc",
		test: testMultiHopHtlcClaims,
	},
	{
		name: "sweep coins",
		test: testSweepAllCoins,
	},
	{
		name: "recovery info",
		test: testGetRecoveryInfo,
	},
	{
		name: "onchain fund recovery",
		test: testOnchainFundRecovery,
	},
	{
		name: "basic funding flow",
		test: testBasicChannelFunding,
	},
	{
		name: "unconfirmed channel funding",
		test: testUnconfirmedChannelFunding,
	},
	{
		name: "update channel policy",
		test: testUpdateChannelPolicy,
	},
	{
		name: "open channel reorg test",
		test: testOpenChannelAfterReorg,
	},
	{
		name: "disconnecting target peer",
		test: testDisconnectingTargetPeer,
	},
	{
		name: "graph topology notifications",
		test: testGraphTopologyNotifications,
	},
	{
		name: "funding flow persistence",
		test: testChannelFundingPersistence,
	},
	{
		name: "channel force closure",
		test: testChannelForceClosure,
	},
	{
		name: "channel balance",
		test: testChannelBalance,
	},
	{
		name: "channel unsettled balance",
		test: testChannelUnsettledBalance,
	},
	{
		name: "single hop invoice",
		test: testSingleHopInvoice,
	},
	{
		name: "sphinx replay persistence",
		test: testSphinxReplayPersistence,
	},
	{
		name: "list channels",
		test: testListChannels,
	},
	{
		name: "update channel status",
		test: testUpdateChanStatus,
	},
	{
		name: "list outgoing payments",
		test: testListPayments,
	},
	{
		name: "max pending channel",
		test: testMaxPendingChannels,
	},
	{
		name: "multi-hop payments",
		test: testMultiHopPayments,
	},
	{
		name: "single-hop send to route",
		test: testSingleHopSendToRoute,
	},
	{
		name: "multi-hop send to route",
		test: testMultiHopSendToRoute,
	},
	{
		name: "send to route error propagation",
		test: testSendToRouteErrorPropagation,
	},
	{
		name: "unannounced channels",
		test: testUnannouncedChannels,
	},
	{
		name: "private channels",
		test: testPrivateChannels,
	},
	{
		name: "private channel update policy",
		test: testUpdateChannelPolicyForPrivateChannel,
	},
	{
		name: "invoice routing hints",
		test: testInvoiceRoutingHints,
	},
	{
		name: "multi-hop payments over private channels",
		test: testMultiHopOverPrivateChannels,
	},
	{
		name: "multiple channel creation and update subscription",
		test: testBasicChannelCreationAndUpdates,
	},
	{
		name: "invoice update subscription",
		test: testInvoiceSubscriptions,
	},
	{
		name: "multi-hop htlc error propagation",
		test: testHtlcErrorPropagation,
	},
	{
		name: "reject onward htlc",
		test: testRejectHTLC,
	},
	// TODO(roasbeef): multi-path integration test
	{
		name: "node announcement",
		test: testNodeAnnouncement,
	},
	{
		name: "node sign verify",
		test: testNodeSignVerify,
	},
	{
		name: "derive shared key",
		test: testDeriveSharedKey,
	},
	{
		name: "async payments benchmark",
		test: testAsyncPayments,
	},
	{
		name: "async bidirectional payments",
		test: testBidirectionalAsyncPayments,
	},
	{
		name: "switch circuit persistence",
		test: testSwitchCircuitPersistence,
	},
	{
		name: "switch offline delivery",
		test: testSwitchOfflineDelivery,
	},
	{
		name: "switch offline delivery persistence",
		test: testSwitchOfflineDeliveryPersistence,
	},
	{
		name: "switch offline delivery outgoing offline",
		test: testSwitchOfflineDeliveryOutgoingOffline,
	},
	{
		// TODO(roasbeef): test always needs to be last as Bob's state
		// is borked since we trick him into attempting to cheat Alice?
		name: "revoked uncooperative close retribution",
		test: testRevokedCloseRetribution,
	},
	{
		name: "failing link",
		test: testFailingChannel,
	},
	{
		name: "garbage collect link nodes",
		test: testGarbageCollectLinkNodes,
	},
	{
		name: "abandonchannel",
		test: testAbandonChannel,
	},
	{
		name: "revoked uncooperative close retribution zero value remote output",
		test: testRevokedCloseRetributionZeroValueRemoteOutput,
	},
	{
		name: "revoked uncooperative close retribution remote hodl",
		test: testRevokedCloseRetributionRemoteHodl,
	},
	{
		name: "revoked uncooperative close retribution altruist watchtower",
		test: testRevokedCloseRetributionAltruistWatchtower,
	},
	{
		name: "data loss protection",
		test: testDataLossProtection,
	},
	{
		name: "query routes",
		test: testQueryRoutes,
	},
	{
		name: "route fee cutoff",
		test: testRouteFeeCutoff,
	},
	{
		name: "send update disable channel",
		test: testSendUpdateDisableChannel,
	},
	{
		name: "streaming channel backup update",
		test: testChannelBackupUpdates,
	},
	{
		name: "export channel backup",
		test: testExportChannelBackup,
	},
	{
		name: "channel backup restore",
		test: testChannelBackupRestore,
	},
	{
		name: "hold invoice sender persistence",
		test: testHoldInvoicePersistence,
	},
	{
		name: "hold invoice force close",
		test: testHoldInvoiceForceClose,
	},
	{
		name: "commitment deadline",
		test: testCommitmentTransactionDeadline,
	},
	{
		name: "cpfp",
		test: testCPFP,
	},
	{
		name: "anchors reserved value",
		test: testAnchorReservedValue,
	},
	{
		name: "macaroon authentication",
		test: testMacaroonAuthentication,
	},
	{
		name: "bake macaroon",
		test: testBakeMacaroon,
	},
	{
		name: "delete macaroon id",
		test: testDeleteMacaroonID,
	},
	{
		name: "immediate payment after channel opened",
		test: testPaymentFollowingChannelOpen,
	},
	{
		name: "external channel funding",
		test: testExternalFundingChanPoint,
	},
	{
		name: "psbt channel funding",
		test: testPsbtChanFunding,
	},
	{
		name: "sendtoroute multi path payment",
		test: testSendToRouteMultiPath,
	},
	{
		name: "sendtoroute amp",
		test: testSendToRouteAMP,
	},
	{
		name: "sendpayment amp",
		test: testSendPaymentAMP,
	},
	{
		name: "sendpayment amp invoice",
		test: testSendPaymentAMPInvoice,
	},
	{
		name: "send multi path payment",
		test: testSendMultiPathPayment,
	},
	{
		name: "REST API",
		test: testRestAPI,
	},
	{
		name: "intercept forwarded htlc packets",
		test: testForwardInterceptor,
	},
	{
		name: "wumbo channels",
		test: testWumboChannels,
	},
	{
		name: "maximum channel size",
		test: testMaxChannelSize,
	},
	{
		name: "connection timeout",
		test: testNetworkConnectionTimeout,
	},
	{
		name: "stateless init",
		test: testStatelessInit,
	},
	{
		name: "wallet import account",
		test: testWalletImportAccount,
	},
	{
		name: "wallet import pubkey",
		test: testWalletImportPubKey,
	},
	{
		name: "etcd_failover",
		test: testEtcdFailover,
	},
	{
		name: "max htlc pathfind",
		test: testMaxHtlcPathfind,
	},
	{
		name: "addpeer config",
		test: testAddPeerConfig,
	},
}
