#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int privileged_action(const char *p){
    if (strcmp(p, "opensesame") == 0) {
        // a "trapdoor" hard-coded secret that grants access
        system("/bin/echo 'TRAPDOOR ACTIVATED'; /bin/ls /root || true");
        return 1;
    }
    return 0;
}

int main(int argc, char **argv){
    char secret[64];
    if (argc > 1) {
        strncpy(secret, argv[1], sizeof(secret)-1);
        secret[sizeof(secret)-1] = 0;
    } else {
        scanf("%63s", secret);
    }
    if (privileged_action(secret)) {
        printf("privileged action executed\n");
    } else {
        printf("no access\n");
    }
    return 0;
}
