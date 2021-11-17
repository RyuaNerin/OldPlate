#include "http.h"

#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

#include "resource.h"
#include "defer.h"

bool getHttp(LPCWSTR host, LPCWSTR path, std::string &body)
{
    HINTERNET hSession = WinHttpOpen(OLDPLATE_PROJECT_NAME, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession == NULL) return false;
    defer(WinHttpCloseHandle(hSession));
        
    if (WinHttpSetTimeouts(hSession, 5000, 5000, 5000, 5000) == FALSE) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (hConnect == NULL) return false;
    defer(WinHttpCloseHandle(hConnect));

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (hRequest == NULL) return false;
    defer(WinHttpCloseHandle(hRequest));

    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, NULL) == NULL) return false;

    if (WinHttpReceiveResponse(hRequest, NULL) == FALSE) return false;

    DWORD dwStatusCode = 0;
    DWORD dwSize = sizeof(dwStatusCode);

    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX) == NULL) return false;
    if (dwStatusCode != 200) return false;

    DWORD dwRead;
    size_t dwOffset;
    do
    {
        dwSize = 0;
        if (WinHttpQueryDataAvailable(hRequest, &dwSize) == FALSE || dwSize == 0)
            break;

        while (dwSize > 0)
        {
            dwOffset = body.size();
            body.resize(dwOffset + dwSize);

            if (WinHttpReadData(hRequest, &body[dwOffset], dwSize, &dwRead) == FALSE || dwRead == 0)
                break;

            body.resize(dwOffset + dwRead);

            dwSize -= dwRead;
        }
    } while (true);

    return false;
}
