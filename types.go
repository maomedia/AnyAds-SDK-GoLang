package anyads

// AdTask представляет собой рекламную задачу, полученную от Ad Engine.
type AdTask struct {
	TaskID     string   `json:"task_id"`
	CampaignID string   `json:"campaign_id"`
	Creative   Creative `json:"creative"`
}

type Creative struct {
	CreativeID string          `json:"creative_id"`
	Type       string          `json:"type"`
	Content    CreativeContent `json:"content"`
}

type CreativeContent struct {
	Text      string   `json:"text,omitempty"`
	Files     []string `json:"files,omitempty"`
	Buttons   [][]Button `json:"buttons,omitempty"`
	ParseMode string   `json:"parse_mode,omitempty"`
}

type Button struct {
	Text string `json:"text"`
	URL  string `json:"url"`
}

// BroadcastHandler - это тип функции-коллбэка, которую предоставит пользователь.
type BroadcastHandler func(task AdTask)