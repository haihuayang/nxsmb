
#include "include/version.hxx"

struct x_build_info_t g_build = {
    .version = BUILD_VERSION,
    .date = BUILD_DATE,
    .build_type = BUILD_TYPE,
    .branch = BUILD_BRANCH,
    .git_hash = BUILD_COMMIT,
};
