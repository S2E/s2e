#ifndef LIBQ_HELPERS

#define LIBQ_HELPERS

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LIBQ_BUILD_BUG_MSG(x, msg) _Static_assert(!(x), msg)
#define LIBQ_BUILD_BUG_ON(x)       LIBQ_BUILD_BUG_MSG(x, "not expecting: " #x)

struct Error;
typedef struct Error Error;

struct Visitor;
typedef struct Visitor Visitor;

#ifndef glue
#define xglue(x, y)  x##y
#define glue(x, y)   xglue(x, y)
#define stringify(s) tostring(s)
#define tostring(s)  #s
#endif

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#ifndef container_of
#define container_of(ptr, type, member)                       \
    ({                                                        \
        const decltype(((type *) 0)->member) *__mptr = (ptr); \
        (type *) ((char *) __mptr - offsetof(type, member));  \
    })
#endif
#else
#ifndef container_of
#define container_of(ptr, type, member)                      \
    ({                                                       \
        const typeof(((type *) 0)->member) *__mptr = (ptr);  \
        (type *) ((char *) __mptr - offsetof(type, member)); \
    })
#endif
#endif

#endif
