#pragma once
#include "base.h"

#ifndef STRING_NULL_TERMINATOR
#define STRING_NULL_TERMINATOR     '\x00'
#endif

namespace wstd
{
    class TextReader
    {
    private:
        const char* _text;
        size_t _length;
        size_t _index;

    public:
        TextReader(const char* text, size_t length);

        char Next(int steps = 1);

        char Peek(int steps = 1) const;

        const char* Current() const;

        template <const char SizeT>
        const char* ReadUntil(const char(&terminators)[SizeT], _Out_ char* term = nullptr)
        {
            char termChar = STRING_NULL_TERMINATOR;
            while (true)
            {
                char peekChar = Peek();
                if (peekChar == STRING_NULL_TERMINATOR)
                    break;

                auto match = (const char*)memchr(terminators, peekChar, SizeT);
                if (match != nullptr)
                {
                    termChar = *match;
                    break;
                }

                Next();
            }

            if (term != nullptr)
                *term = termChar;

            return Current();
        }

        std::string FormatV(const std::vector<std::string>& placeholderArgs);

        std::string Unescape();
    };

    std::string formatv(const char* text, size_t length, const std::vector<std::string>& placeholderArgs);

    std::string formatv(const std::string& text, const std::vector<std::string>& placeholderArgs);


    std::string unescape(const char* text, size_t length);

    std::string unescape(const std::string& text);

}
