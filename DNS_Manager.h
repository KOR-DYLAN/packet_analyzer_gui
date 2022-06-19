#ifndef __DNS_MANAGER_H__
#define __DNS_MANAGER_H__

#include "UDP_Manager.h"
#include <vector>
using namespace std;

typedef struct {
    string    Name;
    string    Type;
    string    Class;
    uint32_t  Time_To_live;
    uint16_t  Resource_Data_Length;
    string   Resource_Data;
} DNS_Message;

typedef struct {
    string Primary_Name;
    string Responsible_authority_Mailbox;
    uint32_t Serial_Number;
    uint32_t Refresh_Interval;
    uint32_t Retry_Interval;
    uint32_t Expire_Limit;
    uint32_t Minimum_Time_To_Live;
} Name_Server_Message;

class CDNS_Manager : public CUDP_Manager {
/* DNS Header Section */
private:
    uint16_t* DNS_Header_Entry;
    uint16_t DNS_Transaction_ID;
    uint16_t DNS_Flags;
    uint16_t DNS_Question_Count;
    uint16_t DNS_Answer_Count;
    uint16_t DNS_Name_Server_Count;
    uint16_t DNS_Additional_Information_Record_Count;
    uint8_t* DNS_Payload_Entry;
    uint16_t DNS_Payload_Length;
    void DNS_Setup_Header();
    void Show_DNS_Header() const;
// Meaning Of DNS Flags 
private:
    bool DNS_Query_Or_Response;
    uint8_t DNS_Operation_Code;
    bool DNS_Authoritative_Answer;
    bool DNS_Truncated;
    bool DNS_Recursion_Desired;
    bool DNS_Recursion_Available;
    uint8_t DNS_Response_Code;
    uint8_t* DNS_Job_Point;
    void DNS_Setup_Header_Flags();
private:
    void Setup_Query_Section();
    string Setup_Domain_Name(uint8_t** ppEntry, bool bMovePtr);
    void Setup_Offset_Name(uint8_t* NameBuf, int curPos, uint16_t Offset);
    void Setup_Response_Section();
    string Get_DNS_Message_Type(uint16_t TypeNum);
    string Get_DNS_Message_Class(uint16_t ClassNum, bool bOpt);
    string Setup_Resource_Data(uint8_t* pRD, uint16_t TypeNum, uint16_t RD_Len);
public:
    vector<DNS_Message> Query_Msg;
    vector<DNS_Message> Answer_Msg;
    vector<Name_Server_Message> Name_Server_Msg;
    void Show_DNS_Query_Msg();
    void Show_DNS_Answer_Msg();
    void Show_Name_Server_Msg();
    void Show_Option_Msg(DNS_Message& ref);
public:
    CDNS_Manager(CUDP_Manager& ref);
    uint8_t* Get_DNS_Entry();
    uint8_t* Get_DNS_Payload_Entry();
    ssize_t Get_DNS_Header_Len();
private:
    void DNS_Initialize();
/* DNS Header Info Getter. */
public:
    uint16_t Get_DNS_Transaction_ID() const;
    uint16_t Get_DNS_Question_Count() const;
    uint16_t Get_DNS_Answer_Count() const;
    uint16_t Get_DNS_Name_Server_Count() const;
    uint16_t Get_DNS_Additional_Information_Record_Count() const;
    uint16_t Get_DNS_Payload_Lenght() const;

    string Get_DNS_Query_Or_Response() const;
    string Get_DNS_Operation_Code() const;
    string Get_DNS_Authoritative_Answer() const;
    string Get_DNS_Truncated() const;
    string Get_DNS_Recursion_Desired() const;
    string Get_DNS_Recursion_Available() const;
    string Get_DNS_Response_Code() const;

public:
    string Get_DNS_Data(uint8_t* EntryPtr, uint32_t len) const;
    virtual void ShowAppData();
};

#endif
