#include <tevent.h>
#include <talloc.h>
#include <stdio.h>
#include <signal.h>

void sighandler(struct tevent_context *ev,
                struct tevent_signal *se,
                int signum,
                int count,
                void *siginfo,
                void *private_data)
{
    return;
}

int main()
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct tevent_context *ev = NULL;
    struct tevent_signal *sig = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        fputs("Out of memory?", stderr);
        goto done;
    }

    ev = tevent_context_init(tmp_ctx);
    if (ev == NULL) {
        fputs("Out of memory?", stderr);
        goto done;
    }

    puts("Registering signal handler...");
    sig = tevent_add_signal(ev, ev, SIGUSR1, 0, sighandler, NULL);
    if (sig == NULL) {
        fputs("Unable to register signal handler!", stderr);
        goto done;
    }

    puts("Unregistering signal handler...");
    TALLOC_FREE(sig);

    puts("Entering tevent loop...");
    tevent_loop_wait(ev);

    puts("We got through the loop! OK");

done:
    talloc_free(tmp_ctx);
    return 0;
}
