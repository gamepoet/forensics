#include <execinfo.h>
#include "backtrace.h"

int forensics_private_backtrace(void** frames, int capacity) {
  return backtrace(frames, capacity);
}
