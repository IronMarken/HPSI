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


int setup(string agreement_name, int poly_modulus, int plain_modulus, string port){
    cout << "Setup invoked" <<endl;
    cout << "Creating channel " << endl;

    // setup stub and channel
    auto channel = grpc::CreateChannel("localhost:"+port, grpc::InsecureChannelCredentials());
    cout << "Creating stub " << endl;
    auto stub = PSIFunctions::NewStub(channel);
    ClientContext context;
    // setup request
    AgreementReq request;
    request.set_name(agreement_name);
    request.set_plain_modulus(plain_modulus);
    request.set_poly_modulus_degree(poly_modulus);
    AgreementRep reply;
    cout << "Sending the setup request to the receiver" << endl;

    // invoking the setup
    Status status = stub->setup(&context, request, &reply);
    if (status.ok()) {
        cout << "Setup invoked successfully!" << endl;
    } else {
        cerr << status.error_code() << ": " << status.error_message() << " RPC failed "<<endl;
        exit(-1);
    }

    // save reply
    cout << "Saving reply on files" << endl;
    ofstream pub_file(agreement_name+"_pub.key");
    ofstream rel_file(agreement_name+"_rel.key");
    ofstream para_file(agreement_name+"_par.par");
    reply.pub().SerializeToOstream(&pub_file);
    reply.rel().SerializeToOstream(&rel_file);
    reply.par().SerializeToOstream(&para_file);

    pub_file.close();
    rel_file.close();
    para_file.close();
    return 0;
}



int main() {
    /* WARNING POLY MODULUS DEGREE SUPPORTED
    +----------------------------------------------------+
    | poly_modulus_degree | max coeff_modulus bit-length |
    +---------------------+------------------------------+
    | 1024                | 27                           |
    | 2048                | 54                           |
    | 4096                | 109                          |
    | 8192                | 218                          |
    | 16384               | 438                          |
    | 32768               | 881                          |
    +---------------------+------------------------------+*/
    auto agreement_name = "test";
    auto poly = 8192;
    auto plain = 1024;
    auto port = "8500";
    setup(agreement_name, poly, plain, port);

}