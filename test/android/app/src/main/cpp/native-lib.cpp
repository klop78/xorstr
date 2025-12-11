#include <jni.h>
#include <string>
#include "../../../../../../include/xorstr.hpp"

extern "C" std::string test_cpp14();
extern "C" std::string test_cpp17();

extern "C" JNIEXPORT jstring JNICALL
Java_com_test_1xorstr_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {

    std::string hello = test_cpp14() + "\n" + test_cpp17();

    return env->NewStringUTF(hello.c_str());
}