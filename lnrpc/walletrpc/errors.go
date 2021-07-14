package walletrpc

import (
	"fmt"
)

// PSBTError wraps certain errors returned during the construction of partially
// signed bitcoin transactions performed by FundPSBT
type PSBTError struct {
	error
}

var _ error = (*PSBTError)(nil)

// ErrUnspentInputNotFound returns an error indicating that a specific unspent
// input in a given list of non-locked UTXOs was not found, and the given
// missing transaction index
func ErrUnspentInputNotFound(idx int) PSBTError {
	return PSBTError{
		fmt.Errorf("input %d not found in list of non-"+
			"locked UTXO", idx),
	}
}

// ErrUnableToFund returns an error indicating that the FundPSBT method failed
// along with the returned error message
func ErrUnableToFund(err error) PSBTError {
	return PSBTError{
		fmt.Errorf("wallet couldn't fund PSBT: %v", err),
	}
}
