#pragma once
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

class FileMapper {
private:
    int _fd;
    size_t _MapSize;
    void* _pView;
public:

    class AlreadyInUseException {};

    FileMapper() noexcept :
        _fd(-1),
        _MapSize(static_cast<size_t>(-1)),
        _pView(reinterpret_cast<void*>(-1)) { }

    void Unmap() noexcept {
        if (_pView != reinterpret_cast<void*>(-1)) {
            munmap(_pView, _MapSize);
            _MapSize = static_cast<size_t>(-1);
            _pView = reinterpret_cast<void*>(-1);
        }
    }

    void Close() noexcept {
        if (_fd != -1) {
            close(_fd);
            _fd = -1;
        }
    }

    bool OpenFile(const char* FilePath) {
        if (_fd != -1)
            throw AlreadyInUseException();
        _fd = open(FilePath, O_RDWR, S_IRUSR | S_IWUSR);
        return _fd != -1;
    }

    bool GetFileSize(off_t& refSize) noexcept {
        struct stat fd_stat = {};
        if (fstat(_fd, &fd_stat) != 0) {
            return false;
        } else {
            refSize = fd_stat.st_size;
            return true;
        }
    }

    bool Map(size_t Size) {
        if (_pView != reinterpret_cast<void*>(-1))
            throw AlreadyInUseException();

        _pView = mmap(nullptr, Size, PROT_READ | PROT_WRITE, MAP_SHARED, _fd, 0);

        if (_pView != reinterpret_cast<void*>(-1)) {
            _MapSize = Size;
            return true;
        } else {
            return false;
        }
    }

    template<typename _Type>
    _Type* GetView() const noexcept {
        return reinterpret_cast<_Type*>(_pView);
    }

    ~FileMapper() {
        Unmap();
        Close();
    }
};

