#ifndef __HTTP_MANAGER_H__
#define __HTTP_MANAGER_H__

#include "TCP_Manager.h"
#include <vector>
using namespace std;

enum class HTTP_Identifier : uint8_t {
    Empty = 0,
    Request_Header = 1,
    Response_Header = 2,
    Data = 3,
};

class CHTTP_Manager : public CTCP_Manager {
public:
    int backCnt;
    HTTP_Identifier ID;

    string HTTP_First_Line;
    vector<string> HTTP_Header;
    vector<int> Data_Length;
    
    int OffsetCnt;
private:
    HTTP_Identifier Identifier(string& ref);
    int HexString2Integer(string& ref);
    void Find_Data_Chunks(bool bBegin);
public:
    CHTTP_Manager(CTCP_Manager& ref);
    uint8_t* Get_HTTP_Entry();
    int GetOffsetCnt();
    ssize_t Get_HTTP_Len();
public:
    virtual void ShowAppData();
    string Get_HTTP_Data() const;
};

#endif
