extern "C" {
#include <base/stddef.h>
#include <base/log.h>
}

#include <string>
#include <thread.h>

namespace {

constexpr int kTestValue = 10;

void foo(int arg) {
  if (arg != kTestValue) exit(EXIT_FAILURE);
}

void MainHandler(void *arg) {
  std::string str = "captured!";
  int i = kTestValue;

  rt::ThreadSpawn([=]{
    log_info("hello! '%s'", str.c_str());
    foo(i);
  });

  rt::ThreadSpawn([&]{
    log_info("hello! '%s'", str.c_str());
    foo(i);
  });

  rt::ThreadYield();
}

} // anonymous namespace

int main(int argc, char *argv[]) {
  int ret;

  ret = runtime_init(MainHandler, NULL, 2);
  if (ret) {
    log_err("failed to start runtime");
    return ret;
  }
  return 0;
}
