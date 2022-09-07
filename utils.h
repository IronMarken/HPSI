#pragma once

#include <iostream>
#include <fstream>
#include <string>

using namespace std;


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