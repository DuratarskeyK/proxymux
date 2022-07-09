package corestructs

import (
	"encoding/json"
	"testing"
	"time"
)

func TestUnmarshalling(t *testing.T) {
	var timeouts Timeouts
	json.Unmarshal([]byte(`{"handshake":4,"connect":8,"read":15,"write":16,"splice":23}`), &timeouts)
	if timeouts.Handshake != 4*time.Second {
		t.Errorf("Expected Handshake to be 4 seconds, got %v", timeouts.Handshake)
	}
	if timeouts.Connect != 8*time.Second {
		t.Errorf("Expected Connect to be 8 seconds, got %v", timeouts.Connect)
	}
	if timeouts.Read != 15*time.Second {
		t.Errorf("Expected Read to be 15 seconds, got %v", timeouts.Read)
	}
	if timeouts.Write != 16*time.Second {
		t.Errorf("Expected Write to be 16 seconds, got %v", timeouts.Write)
	}
	if timeouts.Splice != 23 {
		t.Errorf("Expected Splice to be 23, got %d", timeouts.Splice)
	}
}
