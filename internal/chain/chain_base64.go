package chain

import "encoding/base64"

func decodeStd(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
