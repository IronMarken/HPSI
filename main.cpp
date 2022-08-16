// Test for SEAL configuration
#include "seal/seal.h"
#include <iostream>

using namespace seal;
using namespace std;

int main(){
    EncryptionParameters parms(scheme_type::bfv);
    cout << "SEAL configured correctly!" << endl;
    return 0;
}