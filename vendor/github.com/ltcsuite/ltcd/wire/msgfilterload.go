// Copyright (c) 2014-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"
)

// BloomUpdateType specifies how the filter is updated when a match is found
type BloomUpdateType uint8

const (
	// BloomUpdateNone indicates the filter is not adjusted when a match is
	// found.
	BloomUpdateNone BloomUpdateType = 0

	// BloomUpdateAll indicates if the filter matches any data element in a
	// public key script, the outpoint is serialized and inserted into the
	// filter.
	BloomUpdateAll BloomUpdateType = 1

	// BloomUpdateP2PubkeyOnly indicates if the filter matches a data
	// element in a public key script and the script is of the standard
	// pay-to-pubkey or multisig, the outpoint is serialized and inserted
	// into the filter.
	BloomUpdateP2PubkeyOnly BloomUpdateType = 2
)

const (
	// MaxFilterLoadHashFuncs is the maximum number of hash functions to
	// load into the Bloom filter.
	MaxFilterLoadHashFuncs = 50

	// MaxFilterLoadFilterSize is the maximum size in bytes a filter may be.
	MaxFilterLoadFilterSize = 36000
)

// MsgFilterLoad implements the Message interface and represents a bitcoin
// filterload message which is used to reset a Bloom filter.
//
// This message was not added until protocol version BIP0037Version.
type MsgFilterLoad struct {
	Filter    []byte
	HashFuncs uint32
	Tweak     uint32
	Flags     BloomUpdateType
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgFilterLoad) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	if pver < BIP0037Version {
		str := fmt.Sprintf("filterload message invalid for protocol "+
			"version %d", pver)
		return messageError("MsgFilterLoad.BtcDecode", str)
	}

	var err error
	msg.Filter, err = ReadVarBytes(r, pver, MaxFilterLoadFilterSize,
		"filterload filter size")
	if err != nil {
		return err
	}

	err = readElements(r, &msg.HashFuncs, &msg.Tweak, &msg.Flags)
	if err != nil {
		return err
	}

	if msg.HashFuncs > MaxFilterLoadHashFuncs {
		str := fmt.Sprintf("too many filter hash functions for message "+
			"[count %v, max %v]", msg.HashFuncs, MaxFilterLoadHashFuncs)
		return messageError("MsgFilterLoad.BtcDecode", str)
	}

	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgFilterLoad) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	if pver < BIP0037Version {
		str := fmt.Sprintf("filterload message invalid for protocol "+
			"version %d", pver)
		return messageError("MsgFilterLoad.BtcEncode", str)
	}

	size := len(msg.Filter)
	if size > MaxFilterLoadFilterSize {
		str := fmt.Sprintf("filterload filter size too large for message "+
			"[size %v, max %v]", size, MaxFilterLoadFilterSize)
		return messageError("MsgFilterLoad.BtcEncode", str)
	}

	if msg.HashFuncs > MaxFilterLoadHashFuncs {
		str := fmt.Sprintf("too many filter hash functions for message "+
			"[count %v, max %v]", msg.HashFuncs, MaxFilterLoadHashFuncs)
		return messageError("MsgFilterLoad.BtcEncode", str)
	}

	err := WriteVarBytes(w, pver, msg.Filter)
	if err != nil {
		return err
	}

	return writeElements(w, msg.HashFuncs, msg.Tweak, msg.Flags)
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgFilterLoad) Command() string {
	return CmdFilterLoad
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgFilterLoad) MaxPayloadLength(pver uint32) uint32 {
	// Num filter bytes (varInt) + filter + 4 bytes hash funcs +
	// 4 bytes tweak + 1 byte flags.
	return uint32(VarIntSerializeSize(MaxFilterLoadFilterSize)) +
		MaxFilterLoadFilterSize + 9
}

// NewMsgFilterLoad returns a new bitcoin filterload message that conforms to
// the Message interface.  See MsgFilterLoad for details.
func NewMsgFilterLoad(filter []byte, hashFuncs uint32, tweak uint32, flags BloomUpdateType) *MsgFilterLoad {
	return &MsgFilterLoad{
		Filter:    filter,
		HashFuncs: hashFuncs,
		Tweak:     tweak,
		Flags:     flags,
	}
}
