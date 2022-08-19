#include <iostream>
#include <fstream>
#include <string>
#include <memory>
#include <grpc++/grpc++.h>

#include "seal/seal.h"
#include "rpcProto/services.grpc.pb.h"

using namespace grpc;
using namespace remote;
using namespace seal;
using namespace std;


int main() {
    cout << "Creating channel " << endl;
    auto channel = grpc::CreateChannel("localhost:8500", grpc::InsecureChannelCredentials());
    cout << "Creating stub " << endl;
    auto stub = PSIFunctions::NewStub(channel);
    ClientContext context;
    AgreementReq request;
    cout << "Set request name" << endl;
    request.set_name("Yes");
    AgreementRep reply;
    cout << "Calling the method" << endl;
    Status status = stub->setup(&context, request, &reply);
    if (status.ok()) {
        cout << "pub: " << reply.pub() << " rel: " << reply.rel() << " par: " << reply.par() << endl;
    } else {
        cout << status.error_code() << ": " << status.error_message() << " RPC failed "<<endl;
    }
}