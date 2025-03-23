PROTO_PATH=./api/proto
PROTO_GEN_PATH=$(PROTO_PATH)/generated

generate_proto:
	mkdir -p $(PROTO_GEN_PATH)
	protoc --proto_path $(PROTO_PATH) \
	--go_out=$(PROTO_GEN_PATH) --go_opt=paths=source_relative \
	--go-grpc_out=$(PROTO_GEN_PATH) --go-grpc_opt=paths=source_relative \
	./api/proto/v1/*.proto         

clean:
	rm -rf ./api/proto/generated