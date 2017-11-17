#include <thread.h>

namespace rt {
namespace thread_internal {
// A helper to jump from a C function to a C++ std::function.
void ThreadTrampoline(void *arg) {
  (*static_cast<std::function<void()> *>(arg))();
}
} // namespace thread_internal
} // namespace rt
