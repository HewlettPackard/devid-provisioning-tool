//go:generate protoc --proto_path=. --go_out=plugins=grpc:. --go_opt=paths=source_relative service.proto

package enrollapi
