/*
 * Shared setup for the in-process libxdo harnesses: one private Xvfb and one xdo_t
 * per fuzzer process, created in LLVMFuzzerInitialize and reused for every input.
 *
 * State kept across inputs on purpose: the X server and the xdo_t connection.
 * The fuzzed calls press AND release every key they touch, and libxdo rebinds any
 * scratch keycode it borrows back to NoSymbol before returning, so the keyboard map
 * and key state each input starts from are the same. The only X state an input can
 * leave behind is the focus/pointer of a server with no client windows, which the
 * string parsing under test does not read.
 *
 * X protocol errors: Xlib's default handler calls exit(1). A protocol error is the
 * X server validating and refusing a request (e.g. XTEST BadValue for a numeric
 * keycode below the server's min_keycode, which libxdo passes through unchecked:
 * "3" as a key sequence), not memory corruption in this process. Like an
 * application embedding libxdo, the harness installs a handler that logs and
 * continues, so fuzzing keeps exploring libxdo's own parsing, where ASan/UBSan
 * report the real defects. The script target keeps Xlib's default (the CLI's
 * behavior).
 */
#ifndef MAYHEM_XDO_FUZZ_COMMON_H
#define MAYHEM_XDO_FUZZ_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <X11/Xlib.h>
#include "xdo.h"
#include "xvfb_spawn.h"

static xdo_t *g_xdo;

static int mayhem_x_error_log(Display *dpy, XErrorEvent *ev) {
  char text[256];
  XGetErrorText(dpy, ev->error_code, text, sizeof(text));
  fprintf(stderr, "X protocol error: %s (request %d.%d, resource 0x%lx)\n", text,
          ev->request_code, ev->minor_code, ev->resourceid);
  return 0;
}

static void mayhem_xdo_init(void) {
  const char *disp = mayhem_xvfb_start();
  g_xdo = xdo_new(disp);
  if (g_xdo == NULL) {
    fprintf(stderr, "xdo_new(%s) failed\n", disp);
    abort();
  }
  XSetErrorHandler(mayhem_x_error_log);
}

#endif
