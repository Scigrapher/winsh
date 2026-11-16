package wire

import (
	"errors"
	"testing"
)

func TestParseRejectsExcessiveFieldCount(t *testing.T) {
	// Field 1, wire type 0, value 0: two bytes per field.
	data := make([]byte, 0, (maxFieldsPerMessage+1)*2)
	for i := 0; i <= maxFieldsPerMessage; i++ {
		data = append(data, 0x08, 0x00)
	}
	if _, err := Parse(data); !errors.Is(err, ErrMalformed) {
		t.Fatalf("excessive fields error = %v", err)
	}
}

func TestParseAllowsOrdinaryFieldCount(t *testing.T) {
	data := make([]byte, 0, 16)
	for i := 0; i < 8; i++ {
		data = append(data, 0x08, byte(i))
	}
	if _, err := Parse(data); err != nil {
		t.Fatal(err)
	}
}
