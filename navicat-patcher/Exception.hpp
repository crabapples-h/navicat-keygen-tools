#pragma once

class Exception {
private:
    const char* const _FileName;
    const int _NumberOfLine;
    const char* _CustomMessage;
public:

    Exception(const char* FileName, int Line, const char* Message) noexcept :
        _FileName(FileName),
        _NumberOfLine(Line),
        _CustomMessage(Message) {}

    const char* SourceFile() const noexcept {
        return _FileName;
    }

    int SourceLine() const noexcept {
        return _NumberOfLine;
    }

    const char* CustomMessage() const noexcept {
        return _CustomMessage;
    }

    virtual bool HasErrorCode() const noexcept {
        return false;
    }

    virtual unsigned long ErrorCode() const noexcept {
        return 0;
    }

    virtual const char* ErrorString() const noexcept {
        return nullptr;
    }

};

