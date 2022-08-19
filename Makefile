PATH_PLUGIN=$(shell which grpc_cpp_plugin)

protogen:
	protoc -I . --cpp_out=rpcProto services.proto
	protoc -I . --grpc_out=rpcProto --plugin=protoc-gen-grpc=$(PATH_PLUGIN) services.proto
