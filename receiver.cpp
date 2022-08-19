#include <iostream>
#include <fstream>
#include <string>
#include <grpc++/grpc++.h>
#include <memory>

#include "seal/seal.h"
#include "rpcProto/services.grpc.pb.h"

using namespace grpc;
using namespace remote;
using namespace seal;
using namespace std;

class PSIFunctionsServiceImpl final : public PSIFunctions::Service {
    Status setup(ServerContext* context, const remote::AgreementReq* request,
                 AgreementRep* reply) override {
        cout << "Entered in the function" << endl;
        string prefix(request->name());
        reply->set_pub(prefix + "_pub");
        reply->set_rel(prefix + "_rel");
        reply->set_par(prefix + "_par");

        cout << "received " + prefix + "!" << endl;

        if (prefix.compare("Yes") == 0) {
            cout << "Status ok yes word" << endl;
            return Status::OK;
        } else {
            cout << "Status ok no yes word" << endl;
            return Status::CANCELLED;

        }
    }
};


int main() {
    PSIFunctionsServiceImpl service;
    ServerBuilder builder;
    builder.AddListeningPort("0.0.0.0:8500", grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    std::unique_ptr<Server> server(builder.BuildAndStart());
    cout << "Waiting for a request" << endl;
    server -> Wait();
    cout << "Closing" << endl;
}