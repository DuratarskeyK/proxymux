package corestructs

import (
	"encoding/json"
	"time"
)

type Timeouts struct {
	Handshake time.Duration
	Connect   time.Duration
	Read      time.Duration
	Write     time.Duration
	Splice    uint
}

type timeoutsJSON struct {
	Handshake time.Duration `json:"handshake"`
	Connect   time.Duration `json:"connect"`
	Read      time.Duration `json:"read"`
	Write     time.Duration `json:"write"`
	Splice    uint          `json:"splice"`
}

func (t *Timeouts) UnmarshalJSON(data []byte) error {
	var tj timeoutsJSON
	if err := json.Unmarshal(data, &tj); err != nil {
		return err
	}
	t.Handshake = tj.Handshake * time.Second
	t.Connect = tj.Connect * time.Second
	t.Read = tj.Read * time.Second
	t.Write = tj.Write * time.Second
	t.Splice = tj.Splice

	return nil
}
