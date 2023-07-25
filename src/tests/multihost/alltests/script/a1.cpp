
#include <pwd.h>
#include <unistd.h>
#include <pthread.h>

void *tr(void *) {
        struct passwd pwd;
        char buf[8192];
        struct passwd *res;

        getpwuid_r(getuid(), &pwd, buf, sizeof(buf), &res); }

#define NTH 100
pthread_t t[NTH];
int main()
{
        int i;
        for (i=0; i<NTH; ++i) {
                pthread_create(&t[i], NULL, tr, NULL);
        }
        for (i=0; i<NTH; ++i) {
                pthread_join(t[i], NULL);
        }
        return 0;
}
