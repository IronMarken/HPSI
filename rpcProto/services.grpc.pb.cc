// Generated by the gRPC C++ plugin.
// If you make any local change, they will be lost.
// source: services.proto

#include "services.pb.h"
#include "services.grpc.pb.h"

#include <functional>
#include <grpcpp/impl/codegen/async_stream.h>
#include <grpcpp/impl/codegen/async_unary_call.h>
#include <grpcpp/impl/codegen/channel_interface.h>
#include <grpcpp/impl/codegen/client_unary_call.h>
#include <grpcpp/impl/codegen/client_callback.h>
#include <grpcpp/impl/codegen/message_allocator.h>
#include <grpcpp/impl/codegen/method_handler.h>
#include <grpcpp/impl/codegen/rpc_service_method.h>
#include <grpcpp/impl/codegen/server_callback.h>
#include <grpcpp/impl/codegen/server_callback_handlers.h>
#include <grpcpp/impl/codegen/server_context.h>
#include <grpcpp/impl/codegen/service_type.h>
#include <grpcpp/impl/codegen/sync_stream.h>
namespace remote {

static const char* PSIFunctions_method_names[] = {
  "/remote.PSIFunctions/setup",
  "/remote.PSIFunctions/encrypt",
  "/remote.PSIFunctions/intersection",
  "/remote.PSIFunctions/extraction",
};

std::unique_ptr< PSIFunctions::Stub> PSIFunctions::NewStub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options) {
  (void)options;
  std::unique_ptr< PSIFunctions::Stub> stub(new PSIFunctions::Stub(channel, options));
  return stub;
}

PSIFunctions::Stub::Stub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options)
  : channel_(channel), rpcmethod_setup_(PSIFunctions_method_names[0], options.suffix_for_stats(),::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_encrypt_(PSIFunctions_method_names[1], options.suffix_for_stats(),::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_intersection_(PSIFunctions_method_names[2], options.suffix_for_stats(),::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_extraction_(PSIFunctions_method_names[3], options.suffix_for_stats(),::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  {}

::grpc::Status PSIFunctions::Stub::setup(::grpc::ClientContext* context, const ::remote::AgreementReq& request, ::remote::AgreementRep* response) {
  return ::grpc::internal::BlockingUnaryCall< ::remote::AgreementReq, ::remote::AgreementRep, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), rpcmethod_setup_, context, request, response);
}

void PSIFunctions::Stub::async::setup(::grpc::ClientContext* context, const ::remote::AgreementReq* request, ::remote::AgreementRep* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall< ::remote::AgreementReq, ::remote::AgreementRep, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_setup_, context, request, response, std::move(f));
}

void PSIFunctions::Stub::async::setup(::grpc::ClientContext* context, const ::remote::AgreementReq* request, ::remote::AgreementRep* response, ::grpc::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create< ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_setup_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::remote::AgreementRep>* PSIFunctions::Stub::PrepareAsyncsetupRaw(::grpc::ClientContext* context, const ::remote::AgreementReq& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderHelper::Create< ::remote::AgreementRep, ::remote::AgreementReq, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), cq, rpcmethod_setup_, context, request);
}

::grpc::ClientAsyncResponseReader< ::remote::AgreementRep>* PSIFunctions::Stub::AsyncsetupRaw(::grpc::ClientContext* context, const ::remote::AgreementReq& request, ::grpc::CompletionQueue* cq) {
  auto* result =
    this->PrepareAsyncsetupRaw(context, request, cq);
  result->StartCall();
  return result;
}

::grpc::Status PSIFunctions::Stub::encrypt(::grpc::ClientContext* context, const ::remote::EncryptReq& request, ::remote::EncryptRep* response) {
  return ::grpc::internal::BlockingUnaryCall< ::remote::EncryptReq, ::remote::EncryptRep, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), rpcmethod_encrypt_, context, request, response);
}

void PSIFunctions::Stub::async::encrypt(::grpc::ClientContext* context, const ::remote::EncryptReq* request, ::remote::EncryptRep* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall< ::remote::EncryptReq, ::remote::EncryptRep, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_encrypt_, context, request, response, std::move(f));
}

void PSIFunctions::Stub::async::encrypt(::grpc::ClientContext* context, const ::remote::EncryptReq* request, ::remote::EncryptRep* response, ::grpc::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create< ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_encrypt_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::remote::EncryptRep>* PSIFunctions::Stub::PrepareAsyncencryptRaw(::grpc::ClientContext* context, const ::remote::EncryptReq& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderHelper::Create< ::remote::EncryptRep, ::remote::EncryptReq, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), cq, rpcmethod_encrypt_, context, request);
}

::grpc::ClientAsyncResponseReader< ::remote::EncryptRep>* PSIFunctions::Stub::AsyncencryptRaw(::grpc::ClientContext* context, const ::remote::EncryptReq& request, ::grpc::CompletionQueue* cq) {
  auto* result =
    this->PrepareAsyncencryptRaw(context, request, cq);
  result->StartCall();
  return result;
}

::grpc::Status PSIFunctions::Stub::intersection(::grpc::ClientContext* context, const ::remote::IntersectionReq& request, ::remote::IntersectionRep* response) {
  return ::grpc::internal::BlockingUnaryCall< ::remote::IntersectionReq, ::remote::IntersectionRep, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), rpcmethod_intersection_, context, request, response);
}

void PSIFunctions::Stub::async::intersection(::grpc::ClientContext* context, const ::remote::IntersectionReq* request, ::remote::IntersectionRep* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall< ::remote::IntersectionReq, ::remote::IntersectionRep, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_intersection_, context, request, response, std::move(f));
}

void PSIFunctions::Stub::async::intersection(::grpc::ClientContext* context, const ::remote::IntersectionReq* request, ::remote::IntersectionRep* response, ::grpc::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create< ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_intersection_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::remote::IntersectionRep>* PSIFunctions::Stub::PrepareAsyncintersectionRaw(::grpc::ClientContext* context, const ::remote::IntersectionReq& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderHelper::Create< ::remote::IntersectionRep, ::remote::IntersectionReq, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), cq, rpcmethod_intersection_, context, request);
}

::grpc::ClientAsyncResponseReader< ::remote::IntersectionRep>* PSIFunctions::Stub::AsyncintersectionRaw(::grpc::ClientContext* context, const ::remote::IntersectionReq& request, ::grpc::CompletionQueue* cq) {
  auto* result =
    this->PrepareAsyncintersectionRaw(context, request, cq);
  result->StartCall();
  return result;
}

::grpc::Status PSIFunctions::Stub::extraction(::grpc::ClientContext* context, const ::remote::ExtractionReq& request, ::remote::ExtractionRep* response) {
  return ::grpc::internal::BlockingUnaryCall< ::remote::ExtractionReq, ::remote::ExtractionRep, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), rpcmethod_extraction_, context, request, response);
}

void PSIFunctions::Stub::async::extraction(::grpc::ClientContext* context, const ::remote::ExtractionReq* request, ::remote::ExtractionRep* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall< ::remote::ExtractionReq, ::remote::ExtractionRep, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_extraction_, context, request, response, std::move(f));
}

void PSIFunctions::Stub::async::extraction(::grpc::ClientContext* context, const ::remote::ExtractionReq* request, ::remote::ExtractionRep* response, ::grpc::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create< ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_extraction_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::remote::ExtractionRep>* PSIFunctions::Stub::PrepareAsyncextractionRaw(::grpc::ClientContext* context, const ::remote::ExtractionReq& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderHelper::Create< ::remote::ExtractionRep, ::remote::ExtractionReq, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), cq, rpcmethod_extraction_, context, request);
}

::grpc::ClientAsyncResponseReader< ::remote::ExtractionRep>* PSIFunctions::Stub::AsyncextractionRaw(::grpc::ClientContext* context, const ::remote::ExtractionReq& request, ::grpc::CompletionQueue* cq) {
  auto* result =
    this->PrepareAsyncextractionRaw(context, request, cq);
  result->StartCall();
  return result;
}

PSIFunctions::Service::Service() {
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      PSIFunctions_method_names[0],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< PSIFunctions::Service, ::remote::AgreementReq, ::remote::AgreementRep, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(
          [](PSIFunctions::Service* service,
             ::grpc::ServerContext* ctx,
             const ::remote::AgreementReq* req,
             ::remote::AgreementRep* resp) {
               return service->setup(ctx, req, resp);
             }, this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      PSIFunctions_method_names[1],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< PSIFunctions::Service, ::remote::EncryptReq, ::remote::EncryptRep, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(
          [](PSIFunctions::Service* service,
             ::grpc::ServerContext* ctx,
             const ::remote::EncryptReq* req,
             ::remote::EncryptRep* resp) {
               return service->encrypt(ctx, req, resp);
             }, this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      PSIFunctions_method_names[2],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< PSIFunctions::Service, ::remote::IntersectionReq, ::remote::IntersectionRep, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(
          [](PSIFunctions::Service* service,
             ::grpc::ServerContext* ctx,
             const ::remote::IntersectionReq* req,
             ::remote::IntersectionRep* resp) {
               return service->intersection(ctx, req, resp);
             }, this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      PSIFunctions_method_names[3],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< PSIFunctions::Service, ::remote::ExtractionReq, ::remote::ExtractionRep, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(
          [](PSIFunctions::Service* service,
             ::grpc::ServerContext* ctx,
             const ::remote::ExtractionReq* req,
             ::remote::ExtractionRep* resp) {
               return service->extraction(ctx, req, resp);
             }, this)));
}

PSIFunctions::Service::~Service() {
}

::grpc::Status PSIFunctions::Service::setup(::grpc::ServerContext* context, const ::remote::AgreementReq* request, ::remote::AgreementRep* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status PSIFunctions::Service::encrypt(::grpc::ServerContext* context, const ::remote::EncryptReq* request, ::remote::EncryptRep* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status PSIFunctions::Service::intersection(::grpc::ServerContext* context, const ::remote::IntersectionReq* request, ::remote::IntersectionRep* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status PSIFunctions::Service::extraction(::grpc::ServerContext* context, const ::remote::ExtractionReq* request, ::remote::ExtractionRep* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}


}  // namespace remote

