package subscriptions

type listMetadata struct {
	Version      int    `json:"version"`
	URL          string `json:"url"`
	Format       string `json:"format"`
	ETag         string `json:"etag"`
	LastModified string `json:"last_modified"`
	LastChecked  string `json:"last_checked"`
	LastUpdated  string `json:"last_updated"`
	BackoffUntil string `json:"backoff_until"`
	LastResult   string `json:"last_result"`
	LastError    string `json:"last_error"`
	FailCount    int    `json:"fail_count"`
	Bytes        int64  `json:"bytes"`
}

func defaultMetadata() listMetadata {
	return listMetadata{
		Version:    1,
		Format:     defaultFormat,
		LastResult: "never",
	}
}
