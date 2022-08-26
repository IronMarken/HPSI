#include <iostream>
#include <fstream>
#include <string>
#include <grpc++/grpc++.h>
#include <memory>
#include <thread>
#include <mutex>

#include "seal/seal.h"
#include "rpcProto/services.grpc.pb.h"

using namespace grpc;
using namespace remote;
using namespace seal;
using namespace std;

mutex shutdown_mutex;
std::unique_ptr<Server> server;


class PSIFunctionsServiceImpl final : public PSIFunctions::Service {
    Status setup(ServerContext* context, const remote::AgreementReq* request,
                 AgreementRep* reply) override {
        string agreement_name(request->name());
        cout << "Setup invoked! Agreement name: "+request->name() << endl;

        // setup modulus degrees
        size_t poly_modulus = static_cast<size_t>(request->poly_modulus_degree());
        int plain_modulus = static_cast<int>(request->plain_modulus());

        cout << "Poly modulus degree: "+ to_string(poly_modulus)+"\nPlain  modulus degree: "+ to_string(plain_modulus) << endl;

        // generate file names
        string params_file_name = agreement_name+"_par.par";
        string public_key_file_name = agreement_name+"_pub.key";
        string private_key_file_name = agreement_name+"_priv.key";
        string rel_key_file_name = agreement_name+"_rel.key";

        cout << "generating context" << endl;
        // generate params
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(poly_modulus);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus));
        parms.set_plain_modulus(plain_modulus);

        // generate context
        SEALContext agreement_context(parms);
        cout << "Context generated" << endl;


        // generate keys
        cout << "Generating keys" <<endl;
        KeyGenerator keygen(agreement_context);
        SecretKey private_key = keygen.secret_key();
        PublicKey public_key;
        keygen.create_public_key(public_key);
        RelinKeys relin_keys;
        keygen.create_relin_keys(relin_keys);

        // save keys and params
        ofstream private_key_file;
        ofstream public_key_file;
        ofstream rel_key_file;
        ofstream params_file;

        params_file.open(params_file_name);
        private_key_file.open(private_key_file_name);
        public_key_file.open(public_key_file_name);
        rel_key_file.open(rel_key_file_name);

        // check errors
        if (!private_key_file.is_open() || !public_key_file.is_open() || !rel_key_file.is_open()) {
            cerr << "Error generating files" << endl;
            shutdown_mutex.unlock();
            return Status(StatusCode::ABORTED, "Error opening key files");
        }

        cout << "Saving private key file" << endl;
        // save private key file
        private_key.save(private_key_file);
        private_key_file.close();

        // streams
        stringstream param_stream;
        stringstream rel_stream;
        stringstream pub_stream;

        parms.save(param_stream);
        public_key.save(pub_stream);
        relin_keys.save(rel_stream);

        cout << "Saving params, rel and pub keys files"<<endl;
        // save files
        parms.save(params_file);
        public_key.save(public_key_file);
        relin_keys.save(rel_key_file);

        cout << "Populating the reply" << endl;

        // save values in protobuf
        reply->set_par(param_stream.str());
        reply->set_pub(pub_stream.str());
        reply->set_rel(rel_stream.str());

        // close files
        public_key_file.close();
        rel_key_file.close();
        params_file.close();

        cout << "Setup completed" << endl;
        shutdown_mutex.unlock();
        return Status::OK;
    }
};

void shutdown(){
    shutdown_mutex.lock();
    server->Shutdown();
}



int main() {
    PSIFunctionsServiceImpl service;
    ServerBuilder builder;
    shutdown_mutex.lock();
    builder.AddListeningPort("0.0.0.0:8500", grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    server = builder.BuildAndStart();
    thread th(shutdown);
    cout << "Waiting for a request" << endl;
    server->Wait();
    th.join();
    cout << "Closing" << endl;
}