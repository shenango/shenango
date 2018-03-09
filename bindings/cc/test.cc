extern "C" {
#include <base/stddef.h>
#include <base/log.h>
}

#include <string>
#include "thread.h"
#include "timer.h"

namespace {

constexpr int kTestValue = 10;

void foo(int arg) {
  if (arg != kTestValue) BUG();
}

void MainHandler(void *arg) {
  std::string str = "captured!";
  int i = kTestValue;
  int j = kTestValue;

  rt::Spawn([=]{
    log_info("hello from ThreadSpawn()! '%s'", str.c_str());
    foo(i);
  });

  rt::Spawn([&]{
    log_info("hello from ThreadSpawn()! '%s'", str.c_str());
    foo(i);
    j *= 2;
  });

  rt::Yield();
  if (j != kTestValue * 2) BUG();

  rt::Sleep(1 * rt::kMilliseconds);

  auto th = rt::Thread([&]{
    log_info("hello from rt::Thread! '%s'", str.c_str());
    foo(i);
  });
  th.Join();
}

} // anonymous namespace

int main(int argc, char *argv[]) {
  int ret;

  if (argc < 2) {
    printf("arg must be config file\n");
    return -EINVAL;
  }

  ret = runtime_init(argv[1], MainHandler, NULL);
  if (ret) {
    log_err("failed to start runtime");
    return ret;
  }
  return 0;
}
