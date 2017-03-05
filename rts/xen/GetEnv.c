
#include "Rts.h"
#include "GetEnv.h"

void getProgEnvv(int *out_envc, char **out_envv[]) {
    *out_envc = 0;
    *out_envv = NULL;

    return;
}

void freeProgEnvv(int envc STG_UNUSED, char *envv[] STG_UNUSED) {
    return;
}
