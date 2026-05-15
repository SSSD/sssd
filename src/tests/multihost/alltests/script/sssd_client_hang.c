#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/types.h>
#include <sched.h>

volatile bool started = false;

static void *
routine( void *arg )
{
  char buf[256];
  struct passwd pwbuf, *pw;
  uid_t uid;

  uid = geteuid();
  started = true;
  for(;;) {
#ifdef DISABLE_CANCEL
    int oldstate, state;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);
#endif
    getpwuid_r(uid, &pwbuf, buf, sizeof(buf), &pw);
#ifdef DISABLE_CANCEL
    pthread_setcancelstate(oldstate, &state);
    pthread_testcancel();
#endif
  }
}

int
main( int argc, char *argv[] )
{
  char buf[256];
  struct passwd pwbuf, *pw;
  pthread_t thread;

  pthread_create(&thread, NULL, routine, NULL);
  while(!started)
    sched_yield();
  sleep(3);
  printf( "Cancelling thread\n" );
  while( pthread_cancel(thread) != 0 );
  printf( "Joining...\n");
  pthread_join(thread, NULL);
  printf( "Joined, trying getpwuid_r call\n" );

  getpwuid_r(geteuid(), &pwbuf, buf, sizeof(buf), &pw);
  printf( "Never get here\n" );
}
