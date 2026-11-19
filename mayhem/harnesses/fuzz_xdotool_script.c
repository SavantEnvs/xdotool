/*
 * AFL file-input target: an xdotool script file, run exactly as `xdotool <file>`.
 *
 * xdotool_main() sees an existing file in argv[1] and hands it to script_main(),
 * which tokenizes it (quotes, comments, 4096-byte buffer continuation) and runs
 * every command through context_execute() and the cmd_*.c option parsers into
 * libxdo. Upstream code calls exit() on some paths (X errors, help/version), so
 * this is a whole-process file-input target, not an in-process libFuzzer one.
 *
 * Each execution gets a fresh X server: Xvfb is started AFTER __AFL_INIT(), so
 * every forked execution starts and kills its own server. A script can change
 * server state and never undo it (keydown/mousedown without the release, the
 * pointer position, window and desktop properties, the keymap if it dies while
 * a scratch keycode is bound), so a server shared across executions would make
 * an input's result depend on the inputs before it.
 *
 * The rest of each execution's state is fixed too: the environment is replaced
 * with a small fixed one (PATH, HOME, DISPLAY, plus WORD/NUM/KEY) and the script
 * gets three fixed positional arguments, so the tokenizer's $N / $NAME expansion
 * (xdotool.c script_main) is fuzzed and still depends only on the input.
 *
 * A script is a command interpreter, so inputs that would run commands that are
 * unsafe or can only block are skipped (exit 0 without running):
 *   - exec (runs arbitrary programs), sleep, behave, behave_screen_edge,
 *     selectwindow (waits for a click), windowkill (kills X clients);
 *   - any option that is a getopt_long_only prefix of --sync (waits forever for
 *     a window state change) or --file (type reads an arbitrary path).
 * Command names match with strcasecmp and tokens can be quoted or split across
 * read buffers, so commands are checked case-insensitively on the input with all
 * quotes and whitespace removed (only ever over-rejects), and options on
 * whitespace-split tokens with quotes removed. None of the fixed argument or
 * environment values a $-expansion can produce contains a blocked command or
 * option.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <X11/Xlib.h>
#include "xdo.h"
#include "xdotool.h"
#include "xvfb_spawn.h"

#ifndef __AFL_INIT
#define __AFL_INIT() do { } while (0)
#endif

static const char *const blocked_commands[] = {
  "exec", "sleep", "behave", "selectwindow", "windowkill", NULL,
};
static const char *const blocked_options[] = { "sync", "file", NULL };

static int is_sep(unsigned char c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\0';
}

static int is_option_prefix(const char *tok, size_t len) {
  size_t dashes = 0;
  while (dashes < len && dashes < 2 && tok[dashes] == '-')
    dashes++;
  if (dashes == 0)
    return 0;
  size_t name_len = len - dashes;
  const char *eq = memchr(tok + dashes, '=', name_len);
  if (eq != NULL)
    name_len = (size_t)(eq - (tok + dashes));
  if (name_len == 0)
    return 0;
  for (int i = 0; blocked_options[i] != NULL; i++) {
    if (name_len <= strlen(blocked_options[i]) &&
        strncasecmp(tok + dashes, blocked_options[i], name_len) == 0)
      return 1;
  }
  return 0;
}

static int script_is_unsafe(const unsigned char *data, size_t size) {
  char *folded = malloc(size + 1);
  char *tok = malloc(size + 1);
  size_t flen = 0, tlen = 0;
  int unsafe = 0;
  if (folded == NULL || tok == NULL) {
    free(folded);
    free(tok);
    return 1;
  }
  for (size_t i = 0; i <= size && !unsafe; i++) {
    unsigned char c = i < size ? data[i] : '\0';
    if (c == '"' || c == '\'')
      continue;
    if (is_sep(c)) {
      if (tlen > 0 && is_option_prefix(tok, tlen))
        unsafe = 1;
      tlen = 0;
      continue;
    }
    tok[tlen++] = (char)c;
    folded[flen++] = (char)tolower(c);
  }
  folded[flen] = '\0';
  for (int i = 0; !unsafe && blocked_commands[i] != NULL; i++)
    if (strstr(folded, blocked_commands[i]) != NULL)
      unsafe = 1;
  free(folded);
  free(tok);
  return unsafe;
}

/* Fixed values for the script's $1..$3 and $WORD/$NUM/$KEY (see the header). */
static char *script_argv[] = { "xdotool", NULL, "a", "1", "Return", NULL };

static void fixed_environment(void) {
  clearenv();
  setenv("PATH", "/usr/bin:/bin", 1);
  setenv("HOME", "/nonexistent", 1);
  setenv("WORD", "hello", 1);
  setenv("NUM", "42", 1);
  setenv("KEY", "ctrl+a", 1);
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <xdotool script file>\n", argv[0]);
    return 2;
  }
  __AFL_INIT();

  FILE *f = fopen(argv[1], "rb");
  if (f == NULL) {
    perror(argv[1]);
    return 2;
  }
  size_t cap = 4096, size = 0;
  unsigned char *data = malloc(cap);
  size_t n;
  while (data != NULL && (n = fread(data + size, 1, cap - size, f)) > 0) {
    size += n;
    if (size == cap) {
      unsigned char *grown = realloc(data, cap * 2);
      if (grown == NULL) {
        free(data);
        data = NULL;
        break;
      }
      data = grown;
      cap *= 2;
    }
  }
  fclose(f);
  if (data == NULL)
    return 2;
  int unsafe = script_is_unsafe(data, size);
  free(data);
  if (unsafe)
    return 0;

  /* After __AFL_INIT (afl-fuzz's forkserver reads its own variables there). */
  fixed_environment();
  mayhem_xvfb_start();        /* sets DISPLAY */
  atexit(mayhem_xvfb_stop);   /* exit() paths; a crash still kills it via PDEATHSIG */

  script_argv[1] = argv[1];
  return xdotool_main(5, script_argv);
}
