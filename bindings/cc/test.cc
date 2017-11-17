extern "C" {
#include <base/log.h>
}

#include <string>
#include <thread.h>

static void foo(int arg)
{
  log_info("called foo with '%d'", arg);
}

static void MainHandler(void *arg)
{
  std::string str = "captured!";
  int i = 10;

  rt::ThreadSpawn([=]{
    log_info("hello! '%s'", str.c_str());
    foo(i);
  });
  rt::ThreadYield();
}

int main(int argc, char *argv[])
{
  int ret;

  ret = runtime_init(MainHandler, NULL, 1);
  if (ret) {
    log_err("failed to start runtime");
    return ret;
  }
  return 0;
}
