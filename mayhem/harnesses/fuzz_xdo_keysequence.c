/*
 * libFuzzer harness: libxdo's key-sequence parser, the code behind `xdotool key`.
 * The input is one key sequence string ("ctrl+alt+Delete", "shift+a", "0x41",
 * "super+F2 ...") passed to the public API xdo_send_keysequence_window(), which
 * splits it on '+', resolves symbol aliases, keysym names and numeric keycodes,
 * binds scratch keycodes for unmapped keysyms and sends press+release via XTEST.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "xdo_fuzz_common.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  mayhem_xdo_init();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *seq = malloc(size + 1);
  if (seq == NULL)
    return 0;
  memcpy(seq, data, size);
  seq[size] = '\0';
  xdo_send_keysequence_window(g_xdo, CURRENTWINDOW, seq, 0);
  XSync(g_xdo->xdpy, False);
  free(seq);
  return 0;
}
