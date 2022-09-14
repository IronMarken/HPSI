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


int setup(string agreement_name, long poly_modulus, long plain_modulus,string ip, string port){
    cout << "Setup invoked" <<endl;
    cout << "Creating channel " << endl;

    // setup stub and channel
    auto channel = grpc::CreateChannel(ip + ":" + port, grpc::InsecureChannelCredentials());
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

int encrypt(string file_to_encrypt, string agreement_name, string out_file_name, string ip, string port){
    cout << "Encrypt invoked" << endl;
    cout << "Creating channel " << endl;

    // setup stub and channel
    auto channel = grpc::CreateChannel(ip + ":" + port, grpc::InsecureChannelCredentials());
    cout << "Creating stub " << endl;
    auto stub = PSIFunctions::NewStub(channel);
    ClientContext context;

    // setup request
    EncryptReq request;
    request.set_file_to_encrypt(file_to_encrypt);
    request.set_agreement_name(agreement_name);
    request.set_out_file_name(out_file_name);
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
    ofstream cip_file(out_file_name + ".ctx");
    reply.ciphertexts().SerializeToOstream(&cip_file);

    cip_file.close();
    return 0;
}

int intersection(string cipher_file_name, string plain_file, string agreement_name, string out_file_name, string ip, string port){
    cout << "Intersection computation invoked" << endl;

    // reload context
    cout << "Reloading context..." << endl;
    SEALContext agreement_context = reload_context(agreement_name + "_par.par");

    // load public and rel keys
    cout << "Reloading public key and relinearization key..." << endl;
    PublicKey pub_key = get_public_key(agreement_name + "_pub.key", agreement_context);
    RelinKeys rel_key = get_relin_key(agreement_name + "_rel.key", agreement_context);

    // load ciphertexts from encrypted file
    cout << "Loading ciphertexts" << endl;
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
    auto plain_rows = read_file(plain_file);
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

        cout << "Phase " + to_string(i+1) + "/" + to_string(enc_size) + " completed" << endl;
    }

    cout << "Intersection computation completed" << endl << "Sending result to the receiver" << endl;

    // send result to the receiver
    // setup stub and channel
    auto channel = grpc::CreateChannel(ip + ":" + port, grpc::InsecureChannelCredentials());
    auto stub = PSIFunctions::NewStub(channel);
    ClientContext context;


    request.set_name(out_file_name);
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

int extraction(string agreement_name, string computed_file, string output_file, string receiver_file, string ip,  string port){
    cout << "Extraction invoked" << endl;

    // setup stub and channel
    cout << "Creating channel" << endl;
    auto channel = grpc::CreateChannel(ip + ":" + port, grpc::InsecureChannelCredentials());
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
    output << reply.result();
    output.close();

    return 0;
}


void usage(){
    cout << "Usage:" << endl <<
            "   setup: agree on a fully homomorphic cryptographic scheme" << endl <<
            "       -an: agreement name used as identifier [default = test]" << endl <<
            "       -py: poly modulus [default = 8192]" << endl <<
            "       -pl: plain modulus [default = 2147483648 (strings with max length 4)]" << endl <<
            "       -ip: ip to connect [default = localhost]" << endl <<
            "       -pt: port to connect [default = 8500]" << endl <<
            "   encrypt: encrypt receiver plaintext file" << endl <<
            "       -rf: receiver file to encrypt [default = receiver.txt]" << endl <<
            "       -an: agreement name [default = test]" << endl <<
            "       -of: output file name [default = encrypted]" << endl <<
            "       -ip: ip to connect [default = localhost]" << endl <<
            "       -pt: port to connect [default = 8500]" << endl <<
            "   intersect: homomorphic computes intersection (not in plaintext)" << endl <<
            "       -ef: encrypted file name [default = encrypted]" << endl <<
            "       -sf: sender file name to intersect [default = sender.txt]" << endl <<
            "       -an: agreement name [default = test]" << endl <<
            "       -of: output file name [default = intersection]" << endl <<
            "       -ip: ip to connect [default = localhost]" << endl <<
            "       -pt: port to connect [default = 8500]" << endl <<
            "   extract: intersection plaintext values" << endl <<
            "       -an: agreement name [default = test]" << endl <<
            "       -if: intersection file name [default = intersection]" << endl <<
            "       -of: output file name [default = result]" << endl <<
            "       -rf: receiver plaintext file [default = receiver.txt]" << endl <<
            "       -ip: ip to connect [default = localhost]" << endl <<
            "       -pt: port to connect [default = 8500]" << endl <<
            "   help: show usage info" << endl;
}


int main(int argc, char *argv[]) {
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

    if (argc < 2){
        cout << "Wrong usage" << endl << endl;
        usage();
        return -1;
    }

    // parse command

    // help
    if (!strcmp(argv[1], "help")){
        usage();
    }
    // setup
    else if (!strcmp(argv[1], "setup")){
        // set default values
        string agreement_name = "test";
        long poly = 8192;
        // strings with length 4
        long plain = 2147483648;
        string ip = "localhost";
        string port = "8500";

        // arg parser
        // double i++ in cycle condition and out to fix some wrong arguments
        for(int i = 2; i < argc; i++ ){
            if(!strcmp(argv[i], "-an") && argc > i+1){
                agreement_name = argv[i+1];
                i++;
            } else if(!strcmp(argv[i], "-py") && argc > i+1){
                poly = stol(argv[i+1]);
                i++;
            } else if(!strcmp(argv[i], "-pl") && argc > i+1){
                plain = stol(argv[i+1]);
                i++;
            } else if(!strcmp(argv[i], "-ip") && argc > i+1){
                ip = argv[i+1];
                i++;
            } else if(!strcmp(argv[i], "-pt") && argc > i+1){
                port = argv[i+1];
                i++;
            }
        }

        // print parameters
        cout << "Agreement name: " + agreement_name << endl <<
        "Poly modulus: " + to_string(poly) << endl <<
        "Plain modulus: " + to_string(plain) << endl <<
        "IP: " + ip << endl << "Port: " + port << endl << endl;

        // invoke setup
        setup(agreement_name, poly, plain, ip, port);
    }

    // encrypt
    else if(!strcmp(argv[1], "encrypt")){
        string receiver_file = "receiver.txt";
        string agreement_name = "test";
        string output_file_name = "encrypted";
        string ip = "localhost";
        string port = "8500";

        for(int i = 2; i < argc; i++ ){
            if(!strcmp(argv[i], "-an") && argc > i+1){
                agreement_name = argv[i+1];
                i++;
            } else if(!strcmp(argv[i], "-rf") && argc > i+1){
                receiver_file = argv[i+1];
                i++;
            } else if(!strcmp(argv[i], "-of") && argc > i+1){
                output_file_name = argv[i+1];
                i++;
            } else if(!strcmp(argv[i], "-ip") && argc > i+1){
                ip = argv[i+1];
                i++;
            } else if(!strcmp(argv[i], "-pt") && argc > i+1){
                port = argv[i+1];
                i++;
            }
        }

        // print parameters
        cout << "Receiver file: " + receiver_file << endl <<
        "Agreement name: " + agreement_name << endl <<
        "Output file: " + output_file_name << endl <<
        "IP: " + ip << endl << "Port: " + port << endl << endl;

        //invoke encryption
        encrypt(receiver_file, agreement_name, output_file_name, ip, port);
    }

    //intersect
    else if(!strcmp(argv[1], "intersect")){
        string encrypted_file = "encrypted";
        string sender_file = "sender.txt";
        string agreement_name = "test";
        string output_file_name = "intersection";
        string ip = "localhost";
        string port = "8500";

        for(int i = 2; i < argc; i++ ){
            if(!strcmp(argv[i], "-an") && argc > i+1){
                agreement_name = argv[i+1];
                i++;
            } else if(!strcmp(argv[i], "-ef") && argc > i+1){
                encrypted_file = argv[i+1];
                i++;
            } else if(!strcmp(argv[i], "-sf") && argc > i+1) {
                sender_file = argv[i + 1];
                i++;
            } else if(!strcmp(argv[i], "-of") && argc > i+1){
                output_file_name = argv[i+1];
                i++;
            } else if(!strcmp(argv[i], "-ip") && argc > i+1){
                ip = argv[i+1];
                i++;
            } else if(!strcmp(argv[i], "-pt") && argc > i+1){
                port = argv[i+1];
                i++;
            }
        }

        // print parameters
        cout << "Encrypted file: " + encrypted_file << endl <<
        "Sender file: " + sender_file << endl <<
        "Agreement name: " + agreement_name << endl <<
        "Output file: " + output_file_name << endl <<
        "IP: " + ip << endl << "Port: " + port << endl << endl;


        // invoke intersection
        intersection(encrypted_file, sender_file, agreement_name, output_file_name, ip, port);
    }

    // extraction
    else if(!strcmp(argv[1], "extract")) {
        string agreement_name = "test";
        string intersection_file = "intersection";
        string output_file_name = "result";
        string receiver_plaintext = "receiver.txt";
        string ip = "localhost";
        string port = "8500";

        for(int i = 2; i < argc; i++ ){
            if(!strcmp(argv[i], "-an") && argc > i+1){
                agreement_name = argv[i+1];
                i++;
            } else if(!strcmp(argv[i], "-if") && argc > i+1){
                intersection_file = argv[i+1];
                i++;
            } else if(!strcmp(argv[i], "-rf") && argc > i+1) {
                receiver_plaintext = argv[i+1];
                i++;
            } else if(!strcmp(argv[i], "-of") && argc > i+1){
                output_file_name = argv[i+1];
                i++;
            } else if(!strcmp(argv[i], "-ip") && argc > i+1){
                ip = argv[i+1];
                i++;
            } else if(!strcmp(argv[i], "-pt") && argc > i+1){
                port = argv[i+1];
                i++;
            }
        }

        //print parameters
        cout << "Agreement name: " + agreement_name << endl <<
        "Intersection file: " + intersection_file << endl <<
        "Output file: " + output_file_name << endl <<
        "Receiver file: " + receiver_plaintext << endl <<
        "IP: "  << ip << endl << "Port: " + port << endl << endl;

        // invoke extraction
        extraction(agreement_name, intersection_file, output_file_name, receiver_plaintext, ip, port);
    } else {
        cout << "Command not valid" << endl<< endl;
        usage();
    }
    return 0;
}