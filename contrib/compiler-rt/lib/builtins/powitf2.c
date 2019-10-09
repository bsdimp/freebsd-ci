//===-- powitf2.cpp - Implement __powitf2 ---------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements __powitf2 for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

#include "int_lib.h"

#if _ARCH_PPC

// Returns: a ^ b

COMPILER_RT_ABI long double __powitf2(long double a, si_int b) {
  const int recip = b < 0;
  long double r = 1;
  while (1) {
    if (b & 1)
      r *= a;
    b /= 2;
    if (b == 0)
      break;
    a *= a;
  }
  return recip ? 1 / r : r;
}

#endif
