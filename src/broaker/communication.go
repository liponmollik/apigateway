package broker

import (
	"bytes"
	"io/ioutil"
	"net/http"
)

type Communication struct {
	client *http.Client
}

// Create a new communication instance
func NewCommunication() *Communication {
	return &Communication{
		client: &http.Client{},
	}
}

// Send a message to a service
func (comm *Communication) Send(service Service, endpoint string, payload []byte) ([]byte, error) {
	url := service.Address + endpoint
	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := comm.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}
