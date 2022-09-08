#include <iostream>
#include <fstream>
#include <string>

#include "seal/seal.h"

using namespace std;
using namespace seal;


// read file content
inline vector<string> read_file(const string &file_name){
    ifstream file;
    file.open(file_name);
    vector <string> rows;
    if(file.is_open()) {
        string row;
        // read all lines
        while (getline(file, row)) {
            if (row != ""){
                // let row ends with '\0'
                rows.emplace_back(row.c_str());

            }
        }
        file.close();
    }
    return rows;
}

// managing hex strings
// taken from seal example
inline string uint64_to_hex_string(std::uint64_t value){
    return seal::util::uint_to_hex_string(&value, std::size_t(1));
}

// extend example to strings
inline string string_to_hex_string(const string& string_to_convert) {
    string hex_string;

    for(char c : string_to_convert) {
        string value = uint64_to_hex_string(c);
        hex_string.append(value);
    }
    return hex_string;
}

inline string hex_to_ascii(string hex)
{
    // initialize the ASCII code string as empty.
    string ascii = "";
    for (size_t i = 0; i < hex.length(); i += 2)
    {
        // extract two characters from hex string
        string part = hex.substr(i, 2);

        // change it into base 16 and
        // typecast as the character
        char ch = stoul(part, nullptr, 16);

        // add this char to final ASCII string
        ascii += ch;
    }
    return ascii;
}

// reload context
inline SEALContext reload_context(string param_file_name){
    ifstream param_stream;
    param_stream.open(param_file_name);
    if(!param_stream.is_open()){
        cerr << "Error opening params file" << endl;
        exit(-1);
    }

    EncryptionParameters parms(scheme_type::bfv);
    parms.load(param_stream);
    SEALContext agreement_context(parms);
    param_stream.close();
    return agreement_context;
}

// get public key
inline PublicKey get_public_key(string pub_key_file_name, SEALContext agreement_context){
    ifstream pub_key_stream;
    pub_key_stream.open(pub_key_file_name);
    if(!pub_key_stream.is_open()){
        cerr << "Error opening public key file" << endl;
        exit(-1);
    }

    PublicKey pub_key;
    pub_key.load(agreement_context, pub_key_stream);
    pub_key_stream.close();
    return pub_key;
}

// get relin key
inline RelinKeys get_relin_key(string rel_key_file_name, SEALContext agreement_context){
    ifstream rel_key_stream;
    rel_key_stream.open(rel_key_file_name);
    if(!rel_key_stream.is_open()){
        cerr << "Error opening rel key file" << endl;
        exit(-1);
    }

    RelinKeys rel_key;
    rel_key.load(agreement_context, rel_key_stream);
    rel_key_stream.close();
    return rel_key;
}