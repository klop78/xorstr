#include <jni.h>
#include <string>
#define JM_XORSTR_DISABLE_AVX_INTRINSICS
#include "../../../../../../../include/xorstr.hpp"

extern "C"
std::string test_cpp14() {

    std::string hello = xorstr_("0123456789acpp14");
    return hello;
}