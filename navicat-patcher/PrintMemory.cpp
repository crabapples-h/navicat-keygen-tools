#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>

static jmp_buf env;

static void SIGSEGV_Handler(int sig) {
    siglongjmp(env, 1);
}

//
//  read byte(s) at address `p` as _Type to `out`
//  succeed if return true, otherwise return false
//
template<typename _Type>
static inline bool ProbeForRead(const void* p, void* out) {
    int r = sigsetjmp(env, 1);
    if (r == 0) {
        *reinterpret_cast<_Type*>(out) = *reinterpret_cast<const _Type*>(p);
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
void PrintMemory(const void* from, const void* to, const void* base) {
    const uint8_t* start = reinterpret_cast<const uint8_t*>(from);
    const uint8_t* end = reinterpret_cast<const uint8_t*>(to);
    const uint8_t* base_ptr = reinterpret_cast<const uint8_t*>(base);

    if (start >= end)
        return;

    while (reinterpret_cast<uintptr_t>(start) % 16)
        start--;

    while (reinterpret_cast<uintptr_t>(start) % 16)
        end++;

    void (*prev_handler)(int) = signal(SIGSEGV, SIGSEGV_Handler);
    while (start < end) {
        uint16_t value[16] = {};

        if (base_ptr)
            printf("+0x%p  ", reinterpret_cast<const void*>(start - base_ptr));
        else
            printf("0x%p  ", start);

        for (int i = 0; i < 16; ++i) {
            if (ProbeForRead<uint8_t>(start + i, value + i)) {
                printf("%02x ", value[i]);
            } else {
                value[i] = 0xffff;
                printf("?? ");
            }
        }

        printf(" ");

        for (int i = 0; i < 16; ++i) {
            if (value[i] < 0x20) {
                printf(".");
            } else if (value[i] > 0x7e) {
                printf(".");
            } else {
                printf("%c", value[i]);
            }
        }
        printf("\n");
        start += 0x10;
    }
    signal(SIGSEGV, prev_handler);
}

