#include <stddef.h> // NOLINT
#include <stdint.h> // NOLINT
#include <stdio.h>  // NOLINT
#include <signal.h> // NOLINT
#include <setjmp.h> // NOLINT

static jmp_buf env;

static void SIGSEGV_Handler(int sig) {
    siglongjmp(env, 1);
}

//
//  read byte(s) at address `p` as __Type to `out`
//  succeed if return true, otherwise return false
//
template<typename __Type>
static inline bool ProbeForRead(const void* p, void* out) {
    int r = sigsetjmp(env, 1);
    if (r == 0) {
        *reinterpret_cast<__Type*>(out) = *reinterpret_cast<const __Type*>(p);
        return true;
    } else {
        return false;
    }
}

//
//  Print memory data in [from, to) at least
//  If `base` is not nullptr, print address as offset. Otherwise, as absolute address.
//  NOTICE:
//      `base` must >= `from`
//
namespace nkg {

    void PrintMemory(const void *from, const void *to, const void *base) {
        auto start = reinterpret_cast<const uint8_t *>(from);
        auto end = reinterpret_cast<const uint8_t *>(to);
        auto base_ptr = reinterpret_cast<const uint8_t *>(base);

        if (start >= end)
            return;

        while (reinterpret_cast<uintptr_t>(start) % 16)
            start--;

        while (reinterpret_cast<uintptr_t>(end) % 16)
            end++;

        void (*prev_handler)(int) = signal(SIGSEGV, SIGSEGV_Handler);
        while (start < end) {
            uint16_t value[16] = {};

            if (base_ptr) {
                uintptr_t d = start >= base ? start - base_ptr : base_ptr - start;
                if (start >= base) {
                    printf("+0x%.*zx  ", static_cast<int>(2 * sizeof(void *)), d);
                } else {
                    printf("-0x%.*zx  ", static_cast<int>(2 * sizeof(void *)), d);
                }
            } else {
                printf("0x%.*zx  ", static_cast<int>(2 * sizeof(void *)), reinterpret_cast<uintptr_t >(start));
            }

            for (int i = 0; i < 16; ++i) {
                if (start + i < from) {
                    printf("   ");
                    value[i] = 0xfffe;
                } else if (ProbeForRead<uint8_t>(start + i, value + i)) {
                    printf("%02x ", value[i]);
                } else {
                    printf("?? ");
                    value[i] = 0xffff;
                }
            }

            printf(" ");

            for (int i = 0; i < 16; ++i) {  // NOLINT
                if (0x20 <= value[i] && value[i] < 0x7f) {
                    printf("%c", value[i]);
                } else if (value[i] == 0xfffe) {
                    printf(" ");
                } else {
                    printf(".");
                }
            }

            printf("\n");

            start += 0x10;
        }
        signal(SIGSEGV, prev_handler);
    }

}
