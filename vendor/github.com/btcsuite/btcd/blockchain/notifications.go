// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"fmt"
)

// NotificationType represents the type of a notification message.
type NotificationType int

// NotificationCallback is used for a caller to provide a callback for
// notifications about various chain events.
type NotificationCallback func(*Notification)

// Constants for the type of a notification message.
const (
	// NTBlockAccepted indicates the associated block was accepted into
	// the block chain.  Note that this does not necessarily mean it was
	// added to the main chain.  For that, use NTBlockConnected.
	NTBlockAccepted NotificationType = iota

	// NTBlockConnected indicates the associated block was connected to the
	// main chain.
	NTBlockConnected

	// NTBlockDisconnected indicates the associated block was disconnected
	// from the main chain.
	NTBlockDisconnected
)

// notificationTypeStrings is a map of notification types back to their constant
// names for pretty printing.
var notificationTypeStrings = map[NotificationType]string{
	NTBlockAccepted:     "NTBlockAccepted",
	NTBlockConnected:    "NTBlockConnected",
	NTBlockDisconnected: "NTBlockDisconnected",
}

// String returns the NotificationType in human-readable form.
func (n NotificationType) String() string {
	if s, ok := notificationTypeStrings[n]; ok {
		return s
	}
	return fmt.Sprintf("Unknown Notification Type (%d)", int(n))
}

// Notification defines notification that is sent to the caller via the callback
// function provided during the call to New and consists of a notification type
// as well as associated data that depends on the type as follows:
// 	- NTBlockAccepted:     *btcutil.Block
// 	- NTBlockConnected:    *btcutil.Block
// 	- NTBlockDisconnected: *btcutil.Block
type Notification struct {
	Type NotificationType
	Data interface{}
}

// Subscribe to block chain notifications. Registers a callback to be executed
// when various events take place. See the documentation on Notification and
// NotificationType for details on the types and contents of notifications.
func (b *BlockChain) Subscribe(callback NotificationCallback) {
	b.notificationsLock.Lock()
	b.notifications = append(b.notifications, callback)
	b.notificationsLock.Unlock()
}

// sendNotification sends a notification with the passed type and data if the
// caller requested notifications by providing a callback function in the call
// to New.
func (b *BlockChain) sendNotification(typ NotificationType, data interface{}) {
	// Generate and send the notification.
	n := Notification{Type: typ, Data: data}
	b.notificationsLock.RLock()
	for _, callback := range b.notifications {
		callback(&n)
	}
	b.notificationsLock.RUnlock()
}
