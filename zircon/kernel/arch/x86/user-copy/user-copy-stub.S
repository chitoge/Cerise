// Copyright 2026 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include <lib/arch/asm.h>
#include <lib/code-patching/asm.h>

#include <arch/code-patches/case-id-asm.h>

// The code-patching stub for _x86_copy_to_or_from_user().
//
// This is the equivalent of GN's code_patching_hermetic_stub() target (see
// BUILD.gn), hand-written because the Bazel build does not run
// //zircon/kernel/lib/code-patching/hermetic-stub.py.  The body is a blob of
// trap instructions that physboot overwrites at boot with one of the four
// alternatives built from user-copy.S, chosen by
// SelectX86UserCopyAlternative() in
// <arch/x86/user-copy/selection.h> (see arch/x86/code-patches/code-patches.cc,
// CodePatchId::k_X86CopyToOrFromUser).  Two of those four alternatives bracket
// the copy in stac/clac, so SMAP-capable CPUs get a SMAP-correct copy routine.
//
// The blob size must be at least the size of the largest alternative.  As of
// this writing those are 47/53/61/67 bytes (movsb, movsb_smap, movsq,
// movsq_smap); 80 leaves headroom, and unused trailing bytes are never executed
// because every alternative ends in `ret`.  Undersizing is not silent: physboot
// asserts in Patcher::PatchWithAlternative().
.function _x86_copy_to_or_from_user, global
  .code_patching.blob 80, CASE_ID__X86_COPY_TO_OR_FROM_USER
.end_function
