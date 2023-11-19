#include <wstd/text_reader.h>

namespace wstd
{
    TextReader::TextReader(const char* text, size_t length)
    {
        _text = text;
        _length = length;
        _index = -1;
    }

    char TextReader::Next(int steps)
    {
        if (_index + steps >= _length)
            return STRING_NULL_TERMINATOR;
        _index = _index + steps;
        return _text[_index];
    }

    char TextReader::Peek(int steps) const
    {
        if (_index + steps >= _length)
            return STRING_NULL_TERMINATOR;
        return _text[_index + steps];
    }

    const char* TextReader::Current() const
    {
        return _text + _index + 1;
    }

    std::string TextReader::FormatV(const std::vector<std::string>& placeholderArgs)
    {
        std::string sb;
        size_t defaultIndex = 0;

        while (Peek() != STRING_NULL_TERMINATOR)
        {
            char term = STRING_NULL_TERMINATOR;
            auto nextStart = Current();
            sb.append(nextStart, ReadUntil({ '{' }, &term));
            if (term == '{')
            {
                Next();
                char ec = STRING_NULL_TERMINATOR;
                auto indexStart = Current();
                auto indexText = std::string(indexStart, ReadUntil({ '}' }, &ec));
                if (ec != '}')
                    throw std::exception("Missing placeholder end character '}'.");

                size_t index = indexText.empty() ? defaultIndex++ : (size_t)std::stoll(indexText);
                if (index >= placeholderArgs.size())
                    throw std::exception("Array access out of bounds.");

                sb.append(placeholderArgs[index]);
                Next();
            }
        }

        return sb;
    }

    std::string TextReader::Unescape()
    {
        std::string sb;

        while (Peek() != STRING_NULL_TERMINATOR)
        {
            char term = STRING_NULL_TERMINATOR;
            auto nextStart = Current();
            sb.append(nextStart, ReadUntil({ '\\' }, &term));
            if (term == '\\')
            {
                Next();
                char nextChar = Next();
                switch (nextChar)
                {
                case 'r': nextChar = '\r'; break;
                case 'n': nextChar = '\n'; break;
                case 't': nextChar = '\t'; break;
                case '\\': nextChar = '\\'; break;
                case '"': nextChar = '"'; break;
                case '<': nextChar = '<'; break;
                case '{': nextChar = '{'; break;
                default: throw std::exception("Unknown escape sequence.");
                }

                sb.push_back(nextChar);
            }
        }

        return sb;
    }

    std::string formatv(const char* text, size_t length, const std::vector<std::string>& placeholderArgs)
    {
        TextReader textReader(text, length);
        return textReader.FormatV(placeholderArgs);
    }

    std::string formatv(const std::string& text, const std::vector<std::string>& placeholderArgs)
    {
        return formatv(text.c_str(), text.length(), placeholderArgs);
    }

    std::string unescape(const char* text, size_t length)
    {
        TextReader textReader(text, length);
        return textReader.Unescape();
    }

    std::string unescape(const std::string& text)
    {
        return unescape(text.c_str(), text.length());
    }
}
