/*
 * Every libxdo entry point needs a live X display (xdo_new -> XOpenDisplay).
 * This starts one private Xvfb per fuzzer process (the libFuzzer targets: once,
 * before any input runs; the AFL script target: once per execution).
 *
 * Xvfb's -displayfd makes the server pick a free display number itself and write
 * it to our pipe only once it accepts connections, so there is no polling and no
 * display-number collision between parallel fuzzer instances. The child gets
 * PR_SET_PDEATHSIG so the server dies with the fuzzer.
 */
#define _GNU_SOURCE
#include "xvfb_spawn.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/wait.h>

static char display_name[32];
static pid_t xvfb_pid;

const char *mayhem_xvfb_start(void) {
  if (display_name[0] != '\0')
    return display_name;

  int fds[2];
  if (pipe(fds) != 0) {
    perror("xvfb: pipe");
    abort();
  }
  pid_t pid = fork();
  if (pid < 0) {
    perror("xvfb: fork");
    abort();
  }
  if (pid == 0) {
    char fdarg[16];
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    close(fds[0]);
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
      dup2(devnull, 0);
      dup2(devnull, 1);
      dup2(devnull, 2);
    }
    snprintf(fdarg, sizeof(fdarg), "%d", fds[1]);
    /* Xvfb must not inherit the fuzzer's sanitizer runtime settings. */
    unsetenv("LD_PRELOAD");
    execlp("Xvfb", "Xvfb", "-displayfd", fdarg, "-screen", "0", "640x480x24",
           "-nolisten", "tcp", "-noreset", (char *)NULL);
    _exit(127);
  }
  xvfb_pid = pid;
  close(fds[1]);

  char buf[16] = {0};
  size_t got = 0;
  while (got < sizeof(buf) - 1) {
    ssize_t n = read(fds[0], buf + got, sizeof(buf) - 1 - got);
    if (n <= 0)
      break;
    got += (size_t)n;
    if (memchr(buf, '\n', got) != NULL)
      break;
  }
  close(fds[0]);
  int num = atoi(buf);
  if (got == 0 || buf[0] < '0' || buf[0] > '9') {
    fprintf(stderr, "xvfb: Xvfb did not start (is it installed?)\n");
    abort();
  }
  snprintf(display_name, sizeof(display_name), ":%d", num);
  setenv("DISPLAY", display_name, 1);
  return display_name;
}

void mayhem_xvfb_stop(void) {
  if (xvfb_pid <= 0)
    return;
  kill(xvfb_pid, SIGKILL);
  waitpid(xvfb_pid, NULL, 0);
  xvfb_pid = 0;
  display_name[0] = '\0';
}
