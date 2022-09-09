#include <iostream>
#include <fstream>
#include <string>
#include <grpc++/grpc++.h>
#include <memory>
#include <thread>
#include <mutex>

#include "seal/seal.h"
#include "rpcProto/services.grpc.pb.h"
#include "utils.h"

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
        auto plain_modulus = request->plain_modulus();

        cout << "Poly modulus degree: "+ to_string(poly_modulus)+"\nPlain  modulus degree: "+ to_string(plain_modulus) << endl;

        // generate file names
        string params_file_name = agreement_name+"_par.par";
        string public_key_file_name = agreement_name+"_pub.key";
        string private_key_file_name = agreement_name+"_priv.key";
        string rel_key_file_name = agreement_name+"_rel.key";

        cout << "Generating context..." << endl;
        // generate params
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(poly_modulus);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus));
        parms.set_plain_modulus(plain_modulus);

        // generate context
        SEALContext agreement_context(parms);
        cout << "Context generated" << endl;


        // generate keys
        cout << "Generating keys..." <<endl;
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

        cout << "Saving private key file..." << endl;
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

        cout << "Saving params, rel and pub keys files..."<<endl;
        // save files
        parms.save(params_file);
        public_key.save(public_key_file);
        relin_keys.save(rel_key_file);

        cout << "Populating the reply..." << endl;

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

    Status encrypt(ServerContext* context, const remote::EncryptReq* request,
                   EncryptRep* reply) override {
        string agreement_name = request->agreement_name();
        string file_name = request->file_to_encrypt();
        string file_ext = request->file_ext();
        string file_to_encrypt = file_name + "." + file_ext;

        cout << "Encrypt invoked! Agreement name: "+agreement_name+". File to encrypt: "+ file_to_encrypt << endl;
        cout << "Reloading context from parameters file: ";

        // context regeneration
        SEALContext agreement_context = reload_context(agreement_name+"_par.par");
        cout << "Reloading public key" << endl;
        // public key
        PublicKey pub_key = get_public_key(agreement_name+"_pub.key", agreement_context);

        cout << "Reading plaintext from file..." << endl;

        // read the file to encrypt
        vector<string> rows = read_file(file_to_encrypt);
        if(rows.empty()){
            cerr << "Error opening file to encrypt or the file is empty" << endl;
            shutdown_mutex.unlock();
            return Status(StatusCode::ABORTED, "Error opening file to encrypt or the file is empty");
        }


        // encryption
        Encryptor encryptor(agreement_context, pub_key);
        Ciphertext cp;
        cout << "Starting the encryption" << endl;
        int size = (int)rows.size();
        for (int i=0; i < size; i++){

            string row = rows[i];

            // SEAL needs hex value
            string hex_row = string_to_hex_string(row);
            Plaintext plain(hex_row);
            encryptor.encrypt(plain, cp);

            //Serialize in the protocol buffer
            stringstream cipher_stream;
            cp.save(cipher_stream);

            reply->mutable_ciphertexts()->add_cipher(cipher_stream.str());
            cout << to_string(i+1) + "/" + to_string(size) + " encrypted" << endl;
        }

        cout << "Encryption terminated" << endl;

        // save encrypted file
        cout << "Saving encrypted file" << endl;
        ofstream out_file(agreement_name + "_" + file_name + ".ctx");
        reply->ciphertexts().SerializeToOstream(&out_file);

        shutdown_mutex.unlock();
        return Status::OK;
    }

    Status intersection(ServerContext* context, const remote::IntersectionReq* request,
                   IntersectionRep* reply) override {
        cout << "Intersection invoked" << endl;
        string file_name = request->name() + ".ctx";
        // save file
        ofstream out_file(file_name);
        request->computation_result().SerializeToOstream(&out_file);
        cout << "Saving intersection file" << endl;
        shutdown_mutex.unlock();
        return Status::OK;
    }

    Status extraction(ServerContext* context, const remote::ExtractionReq* request,
                        ExtractionRep* reply) override {
        cout << "Extraction invoked" << endl;

        // get parameters
        string agreement_name = request->agreement_name();
        string computed_file = request->computed_file() + ".ctx";
        string output_file_name = request->output_name();
        string plain_file_name = request->receiver_file_name();

        // reload context and private key
        cout << "Reloading context..." << endl;
        SEALContext agreement_context = reload_context(agreement_name + "_par.par");

        cout << "Reloading private key..." << endl;
        ifstream priv_key_stream;
        priv_key_stream.open(agreement_name + "_priv.key");
        if(!priv_key_stream.is_open()){
            cerr << "Error opening private key file" << endl;
            shutdown_mutex.unlock();
            return Status(StatusCode::ABORTED, "Error opening private key file");;
        }

        SecretKey priv_key;
        priv_key.load(agreement_context, priv_key_stream);
        priv_key_stream.close();

        // load homomorphic computed file
        cout << "Loading ciphertexts..." << endl;
        Ciphertexts encrypted_buff = Ciphertexts();
        ifstream encrypted_stream(computed_file);
        if (!encrypted_stream.is_open()){
            cerr << "Error opening encrypted file" << endl;
            shutdown_mutex.unlock();
            return Status(StatusCode::ABORTED, "Error opening encrypted file");
        }

        encrypted_buff.ParseFromIstream(&encrypted_stream);
        encrypted_stream.close();

        vector<Ciphertext> encrypted_list;
        stringstream cip_stream;
        Ciphertext cp;

        auto cip_list = encrypted_buff.cipher();

        for ( int i=0; i < cip_list.size(); i++ ){
            cip_stream << cip_list.Get(i);
            cp.load(agreement_context, cip_stream);
            encrypted_list.push_back(cp);
        }

        int c_size = encrypted_list.size();

        // loading plaintexts
        cout << "Loading plaintexts" << endl;
        auto plain_rows = read_file(plain_file_name);


        // decryption
        Decryptor decryptor(agreement_context, priv_key);
        cout << "Starting decryption phase" << endl;

        for( int i=0; i < c_size; i++){
            Ciphertext current_cip = encrypted_list[i];
            Plaintext plaintext;

            // check noise budget
            if(decryptor.invariant_noise_budget(current_cip) == 0){
                cerr << "Not enough noise budget" << endl;
                shutdown_mutex.unlock();
                return Status(StatusCode::ABORTED, "Not enough noise budget");
            }

            // decrypt
            decryptor.decrypt(current_cip, plaintext);

            //check result
            if(plaintext.to_string()== "0"){
                cout << "Match found with: "+plain_rows[i] << endl;
                reply->add_result(plain_rows[i]);

            }

            cout << "Phase " + to_string(i+1) + "/" + to_string(c_size) << endl;

        }

        // saving intersection
        cout << "Saving intersection file" << endl;
        ofstream output_stream(output_file_name + ".txt");
        reply->SerializeToOstream(&output_stream);
        output_stream .close();

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