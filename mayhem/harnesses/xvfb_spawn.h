#ifndef MAYHEM_XVFB_SPAWN_H
#define MAYHEM_XVFB_SPAWN_H
/* Start a private Xvfb server for this process and point $DISPLAY at it.
 * Returns the display string (":N"); aborts if the server cannot be started. */
const char *mayhem_xvfb_start(void);
/* Kill and reap the server started by mayhem_xvfb_start() (no-op if none). */
void mayhem_xvfb_stop(void);
#endif
