#pragma once
#include <windows.h>
#include <string>
#include <sys/types.h>
#include "NavicatCrypto.hpp"

#undef __BASE_FILE__
#define __BASE_FILE__ "Helper.hpp"

namespace Helper {

    extern Navicat11Crypto NavicatCipher;

    //
    //  Print memory data in [from, to) at least
    //  If `base` is not nullptr, print address as offset. Otherwise, as absolute address.
    //  NOTICE:
    //      `base` must <= `from`
    //  
    void PrintMemory(const void* from, const void* to, const void* base = nullptr);

    template<typename _Type, bool _Ascending = true>
    void QuickSort(_Type* pArray, off_t begin, off_t end) {
        if (end - begin <= 1)
            return;

        off_t i = begin;
        off_t j = end - 1;
        _Type seperator = static_cast<_Type&&>(pArray[begin]);

        while (i < j) {
            if (_Ascending) {
                while (i < j && seperator <= pArray[j])
                    --j;

                if (i < j)
                    pArray[i++] = static_cast<_Type&&>(pArray[j]);

                while (i < j && pArray[i] <= seperator)
                    ++i;

                if (i < j)
                    pArray[j--] = static_cast<_Type&&>(pArray[i]);
            } else {
                while (i < j && seperator >= pArray[j])
                    --j;

                if (i < j)
                    pArray[i++] = static_cast<_Type&&>(pArray[j]);

                while (i < j && pArray[i] >= seperator)
                    ++i;

                if (i < j)
                    pArray[j--] = static_cast<_Type&&>(pArray[i]);
            }
        }

        pArray[i] = static_cast<_Type&&>(seperator);
        QuickSort<_Type, _Ascending>(pArray, begin, i);
        QuickSort<_Type, _Ascending>(pArray, i + 1, end);
    }

    std::string ConvertToUTF8(PCSTR From, DWORD CodePage = CP_ACP);
    std::string ConvertToUTF8(PCWSTR From);

}

