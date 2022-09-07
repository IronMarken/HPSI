cmake_minimum_required(VERSION 3.18)
project(HPSI VERSION 1.0)

set(CMAKE_CXX_FLAGS "-Wall -Werror")
set(CMAKE_CXX_STANDARD 11)

add_executable(receiver receiver.cpp rpcProto/services.pb.cc rpcProto/services.pb.h rpcProto/services.grpc.pb.cc rpcProto/services.grpc.pb.h utils.h)
add_executable(sender sender.cpp rpcProto/services.pb.cc rpcProto/services.pb.h rpcProto/services.grpc.pb.cc rpcProto/services.grpc.pb.h utils.h)


include(FindProtobuf)
include_directories(${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS services.proto)

target_include_directories(receiver PUBLIC ${CMAKE_BINARY_DIR}/rpcProto)
target_include_directories(sender PUBLIC ${CMAKE_BINARY_DIR}/rpcProto)

find_package(SEAL REQUIRED)
target_link_libraries(receiver SEAL::seal)
target_link_libraries(sender SEAL::seal)

find_package(Protobuf REQUIRED)
target_link_libraries(receiver ${Protobuf_LIBRARIES})
target_link_libraries(sender ${Protobuf_LIBRARIES})

find_package(gRPC CONFIG REQUIRED)
target_link_libraries(receiver gRPC::grpc++)
target_link_libraries(sender gRPC::grpc++)