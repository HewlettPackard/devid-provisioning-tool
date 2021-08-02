build: 
	go build -o ./bin/agent/provisioning-agent ./cmd/agent
	go build -o ./bin/server/provisioning-server ./cmd/server

