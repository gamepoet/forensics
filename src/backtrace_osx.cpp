#include "backtrace.h"
#include <execinfo.h>

int forensics_private_backtrace(void** frames, int capacity) {
  return backtrace(frames, capacity);
}
