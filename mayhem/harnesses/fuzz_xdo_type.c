/*
 * libFuzzer harness: libxdo's text typing, the code behind `xdotool type`.
 * The input is UTF-8 text passed to the public API xdo_enter_text_window(), which
 * decodes it with mbsrtowcs, maps each character to a keysym/keycode (binding a
 * scratch keycode for characters the keymap lacks) and types it via XTEST.
 */
#include <locale.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "xdo_fuzz_common.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  /* A UTF-8 locale, as a library caller typing non-ASCII text would set, so
   * mbsrtowcs decodes multibyte input. Set once, never changed by an input. */
  setlocale(LC_ALL, "C.UTF-8");
  mayhem_xdo_init();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *text = malloc(size + 1);
  if (text == NULL)
    return 0;
  memcpy(text, data, size);
  text[size] = '\0';
  xdo_enter_text_window(g_xdo, CURRENTWINDOW, text, 0);
  XSync(g_xdo->xdpy, False);
  free(text);
  return 0;
}
