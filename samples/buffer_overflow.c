#include <stdio.h>
#include <string.h>

int main() {
    char buf[16];
    // intentionally vulnerable
    scanf("%s", buf);
    printf("You said: %s\n", buf);
    return 0;
}
