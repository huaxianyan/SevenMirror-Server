package relaydelivery

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestRelayDeliveryVectorMatchesCanonicalEncoding(t *testing.T) {
	content, err := os.ReadFile("../test-vectors/relay-delivery-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		DurableSubmissionHex string `json:"durableSubmissionHex"`
		ResumeZeroHex        string `json:"resumeZeroHex"`
		AcknowledgementHex   string `json:"acknowledgementHex"`
		DeliveryHex          string `json:"deliveryHex"`
		CaughtUpHex          string `json:"caughtUpHex"`
		ResetRequiredHex     string `json:"resetRequiredHex"`
	}
	if err := json.Unmarshal(content, &vector); err != nil {
		t.Fatal(err)
	}
	envelope := canonicalEnvelope(t)
	submission, _ := EncodeDurableSubmission(envelope)
	resume, _ := EncodeResume(0)
	acknowledgement, _ := EncodeAcknowledgement(7)
	delivery, _ := EncodeDelivery(7, envelope)
	caughtUp, _ := EncodeCaughtUp(7)
	reset, _ := EncodeResetRequired(9)
	actual := []struct {
		encoded  []byte
		expected string
	}{
		{submission, vector.DurableSubmissionHex},
		{resume, vector.ResumeZeroHex},
		{acknowledgement, vector.AcknowledgementHex},
		{delivery, vector.DeliveryHex},
		{caughtUp, vector.CaughtUpHex},
		{reset, vector.ResetRequiredHex},
	}
	for _, item := range actual {
		if hex.EncodeToString(item.encoded) != item.expected {
			t.Fatal("relay delivery encoding does not match canonical vector")
		}
	}
}

func TestRelayDeliveryMessagesPreserveCanonicalEnvelope(t *testing.T) {
	envelope := canonicalEnvelope(t)
	submission, err := EncodeDurableSubmission(envelope)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeClientMessage(submission)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Kind != ClientEnvelopeDurable || !bytes.Equal(decoded.Envelope, envelope) {
		t.Fatal("durable submission did not preserve the encrypted envelope")
	}
	delivery, err := EncodeDelivery(7, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if string(delivery[:4]) != "SND1" || binary.BigEndian.Uint64(delivery[4:12]) != 7 ||
		!bytes.Equal(delivery[12:], envelope) {
		t.Fatal("server delivery did not preserve the encrypted envelope")
	}
}

func TestRelayDeliveryCursorControlsAreCanonical(t *testing.T) {
	resume, err := EncodeResume(0)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeClientMessage(resume)
	if err != nil || decoded.Kind != ClientResume || decoded.Cursor != 0 {
		t.Fatalf("resume = %+v, error = %v", decoded, err)
	}
	ack, err := EncodeAcknowledgement(9)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err = DecodeClientMessage(ack)
	if err != nil || decoded.Kind != ClientAcknowledge || decoded.Cursor != 9 {
		t.Fatalf("acknowledgement = %+v, error = %v", decoded, err)
	}
	caughtUp, err := EncodeCaughtUp(9)
	if err != nil || string(caughtUp[:4]) != "SND2" || binary.BigEndian.Uint64(caughtUp[4:]) != 9 {
		t.Fatal("caught-up marker is not canonical")
	}
	reset, err := EncodeResetRequired(11)
	if err != nil || string(reset[:4]) != "SNR1" || binary.BigEndian.Uint64(reset[4:]) != 11 {
		t.Fatal("reset marker is not canonical")
	}
}

func TestRelayDeliveryRejectsMalformedControls(t *testing.T) {
	for _, encoded := range [][]byte{
		[]byte("SNC1"),
		append([]byte("SNC2"), make([]byte, 8)...),
		append([]byte("BAD1"), make([]byte, 8)...),
		append([]byte("SNQ1"), canonicalEnvelope(t)[:10]...),
	} {
		if _, err := DecodeClientMessage(encoded); err == nil {
			t.Fatalf("malformed message accepted: %x", encoded)
		}
	}
}

func canonicalEnvelope(t *testing.T) []byte {
	t.Helper()
	content, err := os.ReadFile("../test-vectors/encrypted-envelope-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		FrameHex string `json:"frameHex"`
	}
	if err := json.Unmarshal(content, &vector); err != nil {
		t.Fatal(err)
	}
	encoded, err := hex.DecodeString(vector.FrameHex)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
