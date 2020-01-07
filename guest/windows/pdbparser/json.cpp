#include <windows.h>
#include <string>

// Check whether the given character has to be escaped in a JSON string
_Success_(return)
static BOOL IsSpecialChar(_In_ CHAR Char, _Out_ CHAR *EscapeChar)
{
    switch (Char) {
        case '\b':
            *EscapeChar = 'b';
            return TRUE;

        case '\f':
            *EscapeChar = 'f';
            return TRUE;

        case '\n':
            *EscapeChar = 'n';
            return TRUE;

        case '\r':
            *EscapeChar = 'r';
            return TRUE;

        case '\t':
            *EscapeChar = 't';
            return TRUE;

        case '\"':
            *EscapeChar = '"';
            return TRUE;

        case '\\':
            *EscapeChar = '\\';
            return TRUE;

        default:
            return FALSE;
    }
}

std::string JsonEscapeString(const std::string String)
{
    std::string Ret;

    for (auto it:String) {
        CHAR EscapeChar;
        if (IsSpecialChar(it, &EscapeChar)) {
            Ret = Ret + "\\";
            Ret = Ret + EscapeChar;
        } else {
            Ret = Ret + it;
        }
    }

    return Ret;
}
