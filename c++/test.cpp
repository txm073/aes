#include <string>
#include <iostream>

using namespace std;

extern "C" {
    char* test(char* s = (char*)'hex') { 
        cout << "String: " << s << endl;
        return s;
    }
}