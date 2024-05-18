
#include "dyn_array.h"
#include "dyn_array_test.h"
#include "mem.h"
#include "mem_test.h"
#include "string_test.h"
#include "stx.h"
#include "testlib.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

int global_total_tests;
int global_failed_tests;

int main() {
  int result = (global_failed_tests != 0);

  CHECK_TIME(pool_test(), "Pool test took:");
  CHECK_TIME(arena_test(), "Arena test took:");
  CHECK_TIME(string_test(), "String test took:");
  CHECK_TIME(dyn_array_test(), "Dynamic array test took:");

  printf("%s: %d/%d passed.\e[0m\n",
         result ? "\x1B[31mUnit Tests Failed" : "\x1B[32mUnit Tests Successful",
         global_total_tests - global_failed_tests,
         global_total_tests);
}
