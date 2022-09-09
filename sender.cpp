#include <iostream>
#include <fstream>
#include <string>
#include <memory>
#include <grpc++/grpc++.h>

#include "seal/seal.h"
#include "rpcProto/services.grpc.pb.h"
#include "utils.h"

using namespace grpc;
using namespace remote;
using namespace seal;
using namespace std;


int setup(string agreement_name, long poly_modulus, long plain_modulus, string port){
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

    pub_file << reply.pub();
    rel_file << reply.rel();
    para_file << reply.par();


    pub_file.close();
    rel_file.close();
    para_file.close();
    return 0;
}

int encrypt(string file_name_to_encrypt, string file_ext, string agreement_name, string port){
    cout << "Encrypt invoked" << endl;
    cout << "Creating channel " << endl;

    // setup stub and channel
    auto channel = grpc::CreateChannel("localhost:"+port, grpc::InsecureChannelCredentials());
    cout << "Creating stub " << endl;
    auto stub = PSIFunctions::NewStub(channel);
    ClientContext context;

    // setup request
    EncryptReq request;
    request.set_file_to_encrypt(file_name_to_encrypt);
    request.set_file_ext(file_ext);
    request.set_agreement_name(agreement_name);
    EncryptRep reply;
    cout << "Sending the encrypt request to the receiver" << endl;

    // invoking the encryption
    Status status = stub->encrypt(&context, request, &reply);
    if (status.ok()) {
        cout << "Encrypt invoked successfully!" << endl;
    } else {
        cerr << status.error_code() << ": " << status.error_message() << " RPC failed "<<endl;
        exit(-1);
    }

    // save reply
    cout << "Saving ciphertexts" << endl;
    ofstream cip_file(agreement_name + "_" + file_name_to_encrypt + ".ctx");
    reply.ciphertexts().SerializeToOstream(&cip_file);

    cip_file.close();
    return 0;
}

int intersection(string cipher_file_name, string plain_file, string plain_file_ext, string agreement_name, string port){
    cout << "Intersection computation invoked" << endl;

    // reload context
    cout << "Reloading context..." << endl;
    SEALContext agreement_context = reload_context(agreement_name + "_par.par");

    // load public and rel keys
    cout << "Reloading public key and relinearization key..." << endl;
    PublicKey pub_key = get_public_key(agreement_name + "_pub.key", agreement_context);
    RelinKeys rel_key = get_relin_key(agreement_name + "_rel.key", agreement_context);

    // load ciphertexts from encrypted file
    cout << "Loading encrypted ciphertexts" << endl;
    Ciphertexts encrypted_proto = Ciphertexts();
    ifstream encrypted_stream(cipher_file_name + "." + "ctx");
    if (!encrypted_stream.is_open()){
        cerr << "Error opening encrypted file" << endl;
        exit(-1);
    }

    encrypted_proto.ParseFromIstream(&encrypted_stream);
    encrypted_stream.close();

    vector<Ciphertext> encrypted_list;
    stringstream cip_stream;
    Ciphertext cp;

    auto cip_list = encrypted_proto.cipher();

    for ( int i=0; i < cip_list.size(); i++ ){
        cip_stream << cip_list.Get(i);
        cp.load(agreement_context, cip_stream);
        encrypted_list.push_back(cp);
    }

    //load and encrypt plaintext file
    cout << "Loading and encrypting plaintext file" << endl;
    auto plain_rows = read_file(plain_file + "." + plain_file_ext);
    Encryptor enc(agreement_context, pub_key);
    vector<Ciphertext> sender_list;

    // encrypt and append
    for ( auto row : plain_rows ){
        string hex_row = string_to_hex_string(row);
        Plaintext pl(hex_row);
        Ciphertext cp_s;
        enc.encrypt(pl, cp_s);
        sender_list.push_back(cp_s);
    }

    // homomorphic computations
    cout << "Starting homomorphic computation" << endl;
    int enc_size = encrypted_list.size();

    Evaluator evaluator(agreement_context);

    // grpc request
    IntersectionReq request;

    for ( int i=0; i < enc_size; i++ ){
        Ciphertext partial;
        Ciphertext c = encrypted_list[i];

        // start from random value
        auto value = rand() + 1;
        string hex_value = uint64_to_hex_string(value);
        Plaintext rand(hex_value);
        enc.encrypt(rand, partial);

        // sub and mul for each sender cipher
        for (auto send_c : sender_list){
            Ciphertext sub;
            // subtraction
            evaluator.sub(c, send_c, sub);
            // multiply
            evaluator.multiply_inplace(partial, sub);
            // relinearize
            evaluator.relinearize_inplace(partial, rel_key);
        }

        // save partial result into protocol buffer
        stringstream partial_stream;
        partial.save(partial_stream);
        request.mutable_computation_result()->add_cipher(partial_stream.str());

        cout << "Phase " + to_string(i+1) + "/" + to_string(enc_size) + "completed" << endl;
    }

    cout << "Intersection computation completed" << endl << "Sending result to the receiver" << endl;

    // send result to the receiver
    // setup stub and channel
    auto channel = grpc::CreateChannel("localhost:"+port, grpc::InsecureChannelCredentials());
    auto stub = PSIFunctions::NewStub(channel);
    ClientContext context;


    request.set_name(plain_file + "_intersection");
    IntersectionRep reply;

    // invoking the intersection
    Status status = stub->intersection(&context, request, &reply);
    if (status.ok()) {
        cout << "Intersection invoked successfully!" << endl;
    } else {
        cerr << status.error_code() << ": " << status.error_message() << " RPC failed "<<endl;
        exit(-1);
    }
    return 0;
}

int extraction(string agreement_name, string computed_file, string output_file, string receiver_file, string port){
    cout << "Extraction invoked" << endl;

    // setup stub and channel
    cout << "Creating channel" << endl;
    auto channel = grpc::CreateChannel("localhost:" + port, grpc::InsecureChannelCredentials());
    cout << "Creating stub" << endl;
    auto stub = PSIFunctions::NewStub(channel);
    ClientContext context;

    // setup request
    ExtractionReq request;
    request.set_agreement_name(agreement_name);
    request.set_computed_file(computed_file);
    request.set_output_name(output_file);
    request.set_receiver_file_name(receiver_file);


    // invoking the extraction
    ExtractionRep reply;
    cout << "Sending the extraction request to the receiver" << endl;
    Status status = stub->extraction(&context, request, &reply);
    if (status.ok()) {
        cout << "Extraction invoked successfully!" << endl;
    } else {
        cerr << status.error_code() << ": " << status.error_message() << " RPC failed "<<endl;
        exit(-1);
    }

    // save reply
    cout << "Saving results" << endl;
    ofstream output(output_file + ".txt");
    reply.SerializeToOstream(&output);
    output.close();

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
    string agreement_name = "test";

    auto port = "8500";

    // manage strings with max len 4
    /*long plain = 2147483648;
     auto poly = 8192;
    cout << "Plain modulus degree: "+ to_string(plain) << endl;


    setup(agreement_name, poly, plain, port);*/
    /*ifstream param_stream;
    param_stream.open(agreement_name+"_par.par");
    EncryptionParameters parms(scheme_type::bfv);
    parms.load(param_stream);
    SEALContext agreement_context(parms);
    cout << "Context generated" <<endl;
    param_stream.close();

    ifstream pub_key_stream;
    pub_key_stream.open(agreement_name+"_pub.key");
    PublicKey pub_key;
    pub_key.load(agreement_context, pub_key_stream);
    pub_key_stream.close();
    cout << "pub key loaded correctly" << endl;

    ifstream rel_stream;
    rel_stream.open(agreement_name+"_rel.key");
    RelinKeys rel_keys;
    rel_keys.load(agreement_context, rel_stream);
    rel_stream.close();
    cout << "rel key loaded correctly" << endl;*/

    /*auto agreement_context = reload_context(agreement_name+"_par.par");
    auto pub_key = get_public_key(agreement_name+"_pub.key", agreement_context);
    auto rel_keys = get_relin_key(agreement_name+"_rel.key", agreement_context);


    // encryption
    string file_name = "receiver";
    string ext = "txt";
    encrypt(file_name, ext, agreement_name, port);*/

    // decrypt
    // decrypt from file
    /*string ec_file = agreement_name+"_"+file_name+".ctx";
    string ec_file = agreement_name+"_"+file_name+".ctx";
    vector<string> rows;

    // use protocol buffer to get ciphertexts
    Ciphertexts cp_buff = Ciphertexts();
    ifstream cp_file(ec_file);

    cp_buff.ParseFromIstream(&cp_file);
    auto cipher = cp_buff.cipher();


    rows.reserve(cipher.size());
    for (int i = 0; i < cipher.size(); i++) {
        rows.push_back(cipher.Get(i));
    }

    cout << ec_file << endl;

    ifstream priv_key_stream;
    priv_key_stream.open(agreement_name+"_priv.key");
    SecretKey priv_key;
    priv_key.load(agreement_context, priv_key_stream);
    priv_key_stream.close();
    cout << "priv key loaded correctly" << endl;
    Decryptor decryptor(agreement_context, priv_key);

    stringstream row;


    for(int i=0; i< (int)rows.size(); i++){
        row << rows[i];
        Ciphertext cp;
        Plaintext decrypted;

        cp.load(agreement_context, row);
        decryptor.decrypt(cp, decrypted);
        string hex_dec = decrypted.to_string();
        cout << "hex dec " + hex_dec << endl;
        string str_dec = hex_to_ascii(hex_dec);
        cout << "ascii_dec " + str_dec << endl;
    }*/
    //intersection(string cipher_file_name, string plain_file, string plain_file_ext, string agreement_name, string port)
    //intersection("test_receiver", "sender", "txt", agreement_name, port);

    //extraction(string agreement_name, string computed_file, string output_file, string receiver_file, string port)
    extraction(agreement_name, "sender_intersection", "result", "receiver.txt", port);
}