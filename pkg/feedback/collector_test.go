package feedback

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequest_Validate(t *testing.T) {
	tests := []struct {
		action  Action
		wantErr bool
	}{
		{ActionThumbsUp, false},
		{ActionThumbsDown, false},
		{ActionRegenerate, false},
		{Action("invalid"), true},
	}

	for _, tt := range tests {
		t.Run(string(tt.action), func(t *testing.T) {
			req := &Request{Action: tt.action}
			err := req.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidActions(t *testing.T) {
	actions := ValidActions()
	assert.Len(t, actions, 3)
	assert.Contains(t, actions, "thumbs_up")
	assert.Contains(t, actions, "thumbs_down")
	assert.Contains(t, actions, "regenerate")
}
