package gateway

import (
	"encoding/json"
	"fmt"

	"github.com/a2aproject/a2a-go/v2/a2a"
)

func decodeAgentCard(data []byte) (*a2a.AgentCard, error) {
	var card a2a.AgentCard
	if err := json.Unmarshal(data, &card); err != nil {
		return nil, fmt.Errorf("decode agent card: %w", err)
	}
	return &card, nil
}
