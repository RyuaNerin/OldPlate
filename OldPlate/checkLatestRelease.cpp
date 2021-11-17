#include "checkLatestRelease.h"

#include <string>

#include <json/json.h>

#include "resource.h"
#include "http.h"

RELEASE_RESULT checkLatestRelease()
{
    std::string body;
    if (getHttp(L"api.github.com", L"/repos/RyuaNerin/OldPlate/releases/latest", body))
    {
        Json::CharReaderBuilder                 jo_r_builder;
        const std::unique_ptr<Json::CharReader> jo_r(jo_r_builder.newCharReader());
        Json::Value                             jo;

        if (jo_r->parse(body.c_str(), body.c_str() + body.size(), &jo, nullptr))
        {
            std::string tag_name = jo["tag_name"].asString();
            if (tag_name.compare(OLDPLATE_VERSION_STR) == 0)
            {
                return RELEASE_RESULT::LATEST;
            }
            else
            {
                return RELEASE_RESULT::NEW_RELEASE;
            }
        }

        return RELEASE_RESULT::PARSING_ERROR;
    }

    return RELEASE_RESULT::NETWORK_ERROR;
}
