package monitor

import (
	"crypto/sha256"
	"math/big"
	"crypto/sha1" 
	"crypto/hmac"
	"github.com/specmon/specmon/term"
	"fmt"
	"time"
)

func HMACImpl(args []term.Term) (term.Term, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("hmac requires 2 arguments, got %d", len(args))
	}

	key, err := term.AsBytes(args[0])
	if err != nil {
		return nil, err
	}

	msg, err := term.AsBytes(args[1])
	if err != nil {
		return nil, err
	}

	// Compute digest
	digest := HMACGo(key, msg)
	digestTerm := term.NewConstant(digest)

	// ---------------------------------------------------------
	// LOG A SPECMON EVENT TO STDOUT (for debugging & testing)
	// ---------------------------------------------------------
	event := fmt.Sprintf(
		`{"time":%d,"event":{"name":"pair","type":"function","args":[{"name":"hmac","type":"function","args":[{"name":"k","type":"constant","value":"0x%x"},{"name":"m","type":"constant","value":"0x%x"}]},{"name":"digest","type":"constant","value":"0x%x"}]}}`,
		time.Now().UnixMilli(),
		key,
		msg,
		digest,
	)

	fmt.Println(event)
	// ---------------------------------------------------------

	return digestTerm, nil
}


func HMACGo(key, msg []byte) []byte {
    mac := hmac.New(sha1.New, key)
    mac.Write(msg)
    return mac.Sum(nil)
}

// Example: exp(base, exponent) using big.Int
func ExpImpl(args []term.Term) (term.Term, error) {
	baseBytes, err := term.AsBytes(args[0])
	if err != nil {
		return nil, err
	}

	expBytes, err := term.AsBytes(args[1])
	if err != nil {
		return nil, err
	}

	base := new(big.Int).SetBytes(baseBytes)
	exponent := new(big.Int).SetBytes(expBytes)

	result := new(big.Int).Exp(base, exponent, nil)
	return term.NewConstant(result.Bytes()), nil
}

// Example: SHA-256
func HashImpl(args []term.Term) (term.Term, error) {
	m, err := term.AsBytes(args[0])
	if err != nil {
		return nil, err
	}

	h := sha256.Sum256(m)
	return term.NewConstant(h[:]), nil
}

// Example: Dummy rand() -> fixed bytes
func RandImpl(args []term.Term) (term.Term, error) {
	return term.NewConstant([]byte{0x01, 0x02, 0x03, 0x04}), nil
}

// Call this at init
func init() {
	RegisterFunction("exp", ExpImpl)
	RegisterFunction("hash", HashImpl)
	RegisterFunction("rand", RandImpl)
}
