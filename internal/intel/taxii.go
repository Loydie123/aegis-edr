package intel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"aegis-edr/internal/storage"
)

type STIXBundle struct {
	Type    string       `json:"type"`
	Objects []STIXObject `json:"objects"`
}

type STIXObject struct {
	Type        string   `json:"type"`
	ID          string   `json:"id"`
	Pattern     string   `json:"pattern"`
	PatternType string   `json:"pattern_type"`
	Labels      []string `json:"labels"`
}

type TAXIIClient struct {
	store      *storage.Storage
	httpClient *http.Client
}

func NewTAXIIClient(store *storage.Storage) *TAXIIClient {
	return &TAXIIClient{
		store: store,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *TAXIIClient) IngestSTIXBundle(data []byte) error {
	var bundle STIXBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return err
	}

	if bundle.Type != "bundle" {
		return errors.New("invalid STIX object type: expected bundle")
	}

	for _, obj := range bundle.Objects {
		if obj.Type == "indicator" {
			label := "unknown"
			if len(obj.Labels) > 0 {
				label = obj.Labels[0]
			}
			err := c.store.InsertIndicator(context.Background(), obj.Pattern, obj.PatternType, label)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *TAXIIClient) PollFeed(ctx context.Context, endpointURL, username, password string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", endpointURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/vnd.oasis.taxii+json; version=2.1")
	if username != "" || password != "" {
		req.SetBasicAuth(username, password)
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return errors.New("TAXII server returned non-OK status: " + res.Status)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	return c.IngestSTIXBundle(body)
}
