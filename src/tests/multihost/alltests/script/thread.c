
#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>

static void *client(void *arg)
{
    int i = *((int *)arg);
    struct passwd pwd;
    char buf[10000];
    struct passwd *r;

    for (int c = 0; c < 3; ++c) {
        getpwuid_r(i+c, &pwd, buf, 10000, &r);
    }

    return NULL;
}

int main(void)
{
    pthread_t thread1;
    pthread_t thread2;
    int arg1 = 100000;
    int arg2 = 200000;
    void *t_ret;

    pthread_create(&thread1, NULL, client, &arg1);
    pthread_create(&thread2, NULL, client, &arg2);

    pthread_join(thread1, &t_ret);
    pthread_join(thread2, &t_ret);

    return 0;
}
