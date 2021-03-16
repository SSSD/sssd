#define _GNU_SOURCE /* for pthread_yield */

#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>
#include <pwd.h>
#include <grp.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>



struct data {
    char *group;
    char *host;
    char *user;
    char *domain;
    bool *failed;
};

static void *full_netgroup(void *arg)
{
    int ret;
    size_t c = 0;
    struct data *data = arg;

    do {
        ret = innetgr(data->group, data->host, data->user, data->domain);
        if (ret != 1) {
            *(data->failed) = true;
        }
        c++;
    } while (!*(data->failed) && c<100000);

    pthread_exit(NULL);
}

int main()
{
    pthread_t thread[2];
    bool failed = false;

    struct data data[3] = {{"ng1", "host1", "user924", "domain1", &failed},
                           {"ng2", "host2", "user925", "domain2", &failed},
                           {NULL, NULL, NULL, NULL, NULL}};


    pthread_create(&thread[0], NULL, full_netgroup, &data[0]);
    pthread_create(&thread[1], NULL, full_netgroup, &data[1]);

    pthread_join(thread[1], NULL);
    pthread_join(thread[0], NULL);

    if (failed) {
        printf ("Test failed.\n");
    }

    return failed ? 1 : 0;
}
