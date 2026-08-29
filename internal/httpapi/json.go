package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
)

type registrationRequest struct {
	PairingCode   string `json:"pairing_code"`
	DeviceType    string `json:"device_type"`
	DeviceName    string `json:"device_name"`
	E2EEPublicKey string `json:"e2ee_public_key"`
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}

func encodeID(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }
