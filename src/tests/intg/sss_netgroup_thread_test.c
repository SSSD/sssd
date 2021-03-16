/*
    Helper program to test if innetgr() is thread-safe

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (c) 2021 Red Hat, Inc.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>
#include <pwd.h>
#include <grp.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>



struct data {
    const char *group;
    const char *host;
    const char *user;
    const char *domain;
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
    bool failed[2] = {false, false};

    struct data data[3] = {{"ng1", "host1", "user924", "domain1", &failed[0]},
                           {"ng2", "host2", "user925", "domain2", &failed[1]},
                           {NULL, NULL, NULL, NULL, NULL}};


    pthread_create(&thread[0], NULL, full_netgroup, &data[0]);
    pthread_create(&thread[1], NULL, full_netgroup, &data[1]);

    pthread_join(thread[1], NULL);
    pthread_join(thread[0], NULL);

    if (failed[0] || failed[1]) {
        printf ("Test failed.\n");
        return 1;
    }

    return 0;
}
