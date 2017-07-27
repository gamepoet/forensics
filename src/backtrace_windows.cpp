#include <windows.h>
#include "backtrace.h"

int forensics_private_backtrace(void** frames, int capacity) {
  return RtlCaptureStackBackTrace(0, capacity, frames, nullptr);
}
