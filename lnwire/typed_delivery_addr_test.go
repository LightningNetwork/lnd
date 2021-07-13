package lnwire

import (
	"bytes"
	"testing"
)

// TestDeliveryAddressEncodeDecode tests that we're able to properly
// encode and decode delivery addresses within TLV streams.
func TestDeliveryAddressEncodeDecode(t *testing.T) {
	t.Parallel()

	addr := DeliveryAddress(
		bytes.Repeat([]byte("a"), deliveryAddressMaxSize),
	)

	var extraData ExtraOpaqueData
	err := extraData.PackRecords(&addr)
	if err != nil {
		t.Fatal(err)
	}

	var addr2 DeliveryAddress
	tlvs, err := extraData.ExtractRecords(&addr2)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := tlvs[DeliveryAddrType]; !ok {
		t.Fatalf("DeliveryAddrType not found in records")
	}

	if !bytes.Equal(addr, addr2) {
		t.Fatalf("addr mismatch: expected %x, got %x", addr[:],
			addr2[:])
	}
}
