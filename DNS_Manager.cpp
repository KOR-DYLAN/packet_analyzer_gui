#include "DNS_Manager.h"
#include <arpa/inet.h>
#include <iostream>
#include <cstring>

CDNS_Manager::CDNS_Manager(CUDP_Manager& ref) : CUDP_Manager(ref) {
    this->DNS_Setup_Header();
}

void CDNS_Manager::DNS_Setup_Header() {
    this->DNS_Header_Entry = (uint16_t*)this->pUDP_Payload_Entry;

    this->DNS_Transaction_ID = ntohs(this->DNS_Header_Entry[0]);
    this->DNS_Flags = ntohs(this->DNS_Header_Entry[1]);
    this->DNS_Question_Count = ntohs(this->DNS_Header_Entry[2]);
    this->DNS_Answer_Count = ntohs(this->DNS_Header_Entry[3]);
    this->DNS_Name_Server_Count = ntohs(this->DNS_Header_Entry[4]);
    this->DNS_Additional_Information_Record_Count = ntohs(this->DNS_Header_Entry[5]);
    
    this->DNS_Setup_Header_Flags();
    /////////////////////////////////////////////////////////////////////////////////
    this->DNS_Payload_Entry = (uint8_t*)&this->DNS_Header_Entry[6];
    this->DNS_Job_Point = (uint8_t*)&this->DNS_Header_Entry[6];
    this->DNS_Payload_Length = this->UDP_Payload_Length - 12;
    /////////////////////////////////////////////////////////////////////////////////

    for(int idx = 0; idx < this->DNS_Question_Count; idx++)
        this->Setup_Query_Section();
    
    int ResponseCount = this->DNS_Answer_Count + this->DNS_Name_Server_Count + this->DNS_Additional_Information_Record_Count;
    for(int idx = 0; idx < ResponseCount; idx++)
        this->Setup_Response_Section();
}

uint8_t* CDNS_Manager::Get_DNS_Entry() {
    return this->Get_UDP_Payload_Entry();
}

uint8_t* CDNS_Manager::Get_DNS_Payload_Entry() {
    return this->Get_DNS_Entry() + this->Get_DNS_Header_Len();
}

ssize_t CDNS_Manager::Get_DNS_Header_Len() {
    return 12;
}

void CDNS_Manager::DNS_Setup_Header_Flags() {
    this->DNS_Query_Or_Response = (bool)((this->DNS_Flags & 0b1000000000000000) >> 15);
    this->DNS_Operation_Code = (uint8_t)((this->DNS_Flags & 0b0111100000000000) >> 11);
    this->DNS_Authoritative_Answer = (bool)((this->DNS_Flags & 0b0000010000000000) >> 10);
    this->DNS_Truncated = (bool)((this->DNS_Flags & 0b0000001000000000) >> 9);
    this->DNS_Recursion_Desired = (bool)((this->DNS_Flags & 0b0000000100000000) >> 8);
    this->DNS_Recursion_Available = (bool)((this->DNS_Flags & 0b0000000010000000) >> 7);
    this->DNS_Response_Code = (uint8_t)(this->DNS_Flags & 0b0000000000001111);
}

void CDNS_Manager::Setup_Query_Section() {
    DNS_Message newMsg;

    newMsg.Name = Setup_Domain_Name(&this->DNS_Job_Point, true);
    newMsg.Type = this->Get_DNS_Message_Type((this->DNS_Job_Point[0] << 8) | this->DNS_Job_Point[1]);
    newMsg.Class = this->Get_DNS_Message_Class((this->DNS_Job_Point[2] << 8) | this->DNS_Job_Point[3], false);

    this->DNS_Job_Point = &this->DNS_Job_Point[4];

    Query_Msg.push_back(newMsg);
}

void CDNS_Manager::Setup_Response_Section() {
    DNS_Message newMsg;
    uint8_t* pRD;

    newMsg.Name = Setup_Domain_Name(&this->DNS_Job_Point, true);
    newMsg.Type = this->Get_DNS_Message_Type((this->DNS_Job_Point[0] << 8) | this->DNS_Job_Point[1]);
    newMsg.Class = this->Get_DNS_Message_Class((this->DNS_Job_Point[2] << 8) | this->DNS_Job_Point[3], 
                                                newMsg.Type == "[ Option ]");
    newMsg.Time_To_live = 
        (this->DNS_Job_Point[4] << 24) |
        (this->DNS_Job_Point[5] << 16) |
        (this->DNS_Job_Point[6] << 8) |
        this->DNS_Job_Point[7];
    newMsg.Resource_Data_Length = (this->DNS_Job_Point[8] << 8) | this->DNS_Job_Point[9];
    newMsg.Resource_Data = 
        this->Setup_Resource_Data(
            &this->DNS_Job_Point[10],
            (this->DNS_Job_Point[0] << 8) | this->DNS_Job_Point[1], 
            newMsg.Resource_Data_Length
        );

    this->DNS_Job_Point = &this->DNS_Job_Point[10 + newMsg.Resource_Data_Length];

    Answer_Msg.push_back(newMsg);
}

string CDNS_Manager::Setup_Domain_Name(uint8_t** ppEntry, bool bMovePtr) {
    char NameBuf[256] = { 0 };
    char* NameEntry;
    volatile int curPos = -1;

    while((*ppEntry)[++curPos] != '\0') {
        if(((*ppEntry)[curPos] & 0xC0) == uint8_t(0xC0)) {   
            this->Setup_Offset_Name(
                (uint8_t*)NameBuf, 
                curPos, 
                (((*ppEntry)[curPos] << 8) & 0x1F) | (*ppEntry)[curPos + 1]
            );
            
            curPos += 1;
            break;
        }
        else {
            NameBuf[curPos] = (*ppEntry)[curPos];  
        }
    }

    int idx = -1;
    while(NameBuf[++idx] != '\0') {
        if(NameBuf[idx] < ' ')
            NameBuf[idx] = '.';
    }
  
    NameEntry = ((*NameBuf) == '.') ? &NameBuf[1] : NameBuf;

    if(bMovePtr)
        (*ppEntry) += (curPos + 1);

    if(NameEntry[0] == 0)
        return "[ " + string("Root") + " ]";
    else
        return "[ " + string(NameEntry) + " ]";
}

void CDNS_Manager::Setup_Offset_Name(uint8_t* NameBuf, int curPos, uint16_t Offset) {
    int idx = -1;
    uint8_t* ptr = this->pUDP_Payload_Entry;

    while(ptr[Offset + (++idx)] != '\0') {
        if((ptr[Offset + idx] & uint8_t(0xC0)) == uint8_t(0xC0)) {
            this->Setup_Offset_Name(NameBuf, curPos,  ((ptr[Offset + idx] << 8) & 0x1F) | ptr[Offset + idx + 1]);
            break;
        }
        else {
            NameBuf[curPos] = ptr[Offset + idx];   
            curPos += 1; 
        }
    }
}

string CDNS_Manager::Get_DNS_Message_Type(uint16_t TypeNum) {
    switch(TypeNum) {
    case 1: 
        return string("[ IPv4 Address ]");   
    case 2: 
        return string("[ Name Server ]");   
    case 5: 
        return string("[ Canonical Name ]");
    case 6:
        return string("[ Start of Authority ]");
    case 12:
        return string("[ Pointer ]");
    case 13:
        return string("[ Host Information ]");
    case 15:
        return string("[ Mail Exchange ]");
    case 16:
        return string("[ Text ]");
    case 28:
        return string("[ IPv6 Address ]");
    case 41:
        return string("[ Option ]");
    case 252:
        return string("[ Request for full DNS zone forwarding ]");
    case 255:
        return string("[ Request for all records ]");  
    default:
        return string("[ Unknown ]");   
    }
}

string CDNS_Manager::Get_DNS_Message_Class(uint16_t ClassNum, bool bOpt) {
    char buf[10];
    if(bOpt) {
        sprintf(buf, "%u", ClassNum);
        return string(buf);
    }

    switch(ClassNum) {
    case 1:
        return string("[ Internet ]");
    case 3:
        return string("[ COAS Network ]");
    case 4:
        return string("[ Hesoid Server ]");
    default:
        return string("[ Unknown ]");
    }
}

string CDNS_Manager::Setup_Resource_Data(uint8_t* pRD, uint16_t TypeNum, uint16_t RD_Len) {
    uint8_t Buf[128] = { 0 };
    volatile int curPos;
    char* NameEntry;
    Name_Server_Message newNS_Msg;

    switch(TypeNum) {
    case 1: // [ IPv4 Address ]
        sprintf((char*)Buf, "%u.%u.%u.%u", pRD[0], pRD[1], pRD[2], pRD[3]);
        break;
    case 28: // [ IPv6 Address ]
        sprintf((char*)Buf, "%X:%X:%X:%X:%X:%X:%X:%X", 
            (pRD[0] << 8) | pRD[1], 
            (pRD[2] << 8) | pRD[3], 
            (pRD[4] << 8) | pRD[5], 
            (pRD[6] << 8) | pRD[7],
            (pRD[8] << 8) | pRD[9],
            (pRD[10] << 8) | pRD[11],
            (pRD[12] << 8) | pRD[13],
            (pRD[14] << 8) | pRD[15]
        );
        break;
    case 2: // [ Name Server ]
        break;
    case 6: // [ Start of Authority ]
        newNS_Msg.Minimum_Time_To_Live = (pRD[RD_Len - 4] << 24) | (pRD[RD_Len - 3] << 16) | (pRD[RD_Len - 2] << 8) | (pRD[RD_Len - 1]);
        newNS_Msg.Expire_Limit = (pRD[RD_Len - 8] << 24) | (pRD[RD_Len - 7] << 16) | (pRD[RD_Len - 6] << 8) | (pRD[RD_Len - 5]);
        newNS_Msg.Retry_Interval = (pRD[RD_Len - 12] << 24) | (pRD[RD_Len - 11] << 16) | (pRD[RD_Len - 10] << 8) | (pRD[RD_Len - 9]);
        newNS_Msg.Refresh_Interval = (pRD[RD_Len - 16] << 24) | (pRD[RD_Len - 15] << 16) | (pRD[RD_Len - 14] << 8) | (pRD[RD_Len - 13]);
        newNS_Msg.Serial_Number = (pRD[RD_Len - 20] << 24) | (pRD[RD_Len - 19] << 16) | (pRD[RD_Len - 18] << 8) | (pRD[RD_Len - 17]);
        newNS_Msg.Primary_Name = this->Setup_Domain_Name(&pRD, true);
        newNS_Msg.Responsible_authority_Mailbox = this->Setup_Domain_Name(&pRD, true);
        Name_Server_Msg.push_back(newNS_Msg);
        return string();   
    case 5: // [ Canonical Name ]
    
    case 13: // [ Host Information ]
    case 15: // [ Mail Exchange ]   
    case 16: // [ Text ]  
        return this->Setup_Domain_Name(&pRD, false);
    default: // [ Unknown ]
        sprintf((char*)Buf, "[ Unknown ]");
        break;
    }

    return string((char*)Buf);
}

void CDNS_Manager::Show_DNS_Query_Msg() {
    cout << "[ ------------------ Query ------------------ ]" << endl;
    for(int idx = 0; idx < Query_Msg.size(); idx++) {
            cout << "[ Name                    ] : " << Query_Msg[idx].Name << endl;
            cout << "[ Type                    ] : " << Query_Msg[idx].Type << endl;
            cout << "[ Class                   ] : " << Query_Msg[idx].Class << endl << endl;
    }
}

void CDNS_Manager::Show_DNS_Answer_Msg() {
    cout << "[ ------------------ Answer ------------------ ]" << endl;
    for(int idx = 0; idx < Answer_Msg.size(); idx++) {
        if(Answer_Msg[idx].Type != "[ Option ]") {
            cout << "[ Name                    ] : " << Answer_Msg[idx].Name << endl;
            cout << "[ Type                    ] : " << Answer_Msg[idx].Type << endl;
            cout << "[ Class                   ] : " << Answer_Msg[idx].Class << endl;
            cout << "[ Time To Live      (sec) ] : " << Answer_Msg[idx].Time_To_live << endl;
            cout << "[ Resource Data Len(byte) ] : " << Answer_Msg[idx].Resource_Data_Length << endl;

            if(Answer_Msg[idx].Type == "[ Start of Authority ]")
                this->Show_Name_Server_Msg();
            else
                cout << "[ Resource Data           ] : " << Answer_Msg[idx].Resource_Data << endl << endl;
        }
        else
            this->Show_Option_Msg(Answer_Msg[idx]);
    }
}

void CDNS_Manager::Show_Name_Server_Msg() {
    cout << "[ ------------------ Authority ------------------ ]" << endl;
    for(int idx = 0; idx < Name_Server_Msg.size(); idx++) {
        cout << "[ Primay Server Name       ] : " << Name_Server_Msg[idx].Primary_Name << endl;
        cout << "[ Authority Mailbox        ] : " << Name_Server_Msg[idx].Responsible_authority_Mailbox << endl;
        cout << "[ Serial Number            ] : " << Name_Server_Msg[idx].Serial_Number << endl;
        cout << "[ Serial Number            ] : " << Name_Server_Msg[idx].Serial_Number << endl;
        cout << "[ Refresh Interval    (sec)] : " << Name_Server_Msg[idx].Refresh_Interval <<endl;
        cout << "[ Retry Interval      (sec)] : " << Name_Server_Msg[idx].Retry_Interval << endl;
        cout << "[ Expire Limit        (sec)] : " << Name_Server_Msg[idx].Expire_Limit << endl;
        cout << "[ Minimum Time To Live(sec)] : " << Name_Server_Msg[idx].Minimum_Time_To_Live << endl << endl;
    }
}

void CDNS_Manager::Show_Option_Msg(DNS_Message& ref) {
    uint8_t RcodeEx = (ref.Time_To_live & 0xFF000000) >> 24;
    uint8_t Version = (ref.Time_To_live & 0x00FF0000) >> 16;
    bool D0 = (ref.Time_To_live & 0x00008000);
    uint16_t Z = (ref.Time_To_live & 0x0000007F);

    cout << "[ ------------------ Option ------------------ ]" << endl;
    cout << "[ Name                    ] : " << ref.Name << endl;
    cout << "[ Type                    ] : " << ref.Type << endl;
    cout << "[ UDP Payload Size (byte))] : " << ref.Class << endl;
    cout << "[ Extended RCODE          ] : " << (uint16_t)RcodeEx << endl;
    cout << "[ Version                 ] : " << (uint16_t)Version << endl;
    cout << "[ D0 bit                  ] : " << D0 << endl;
    cout << "[ Z                       ] : " << Z << endl;
    cout << "[ Length Of All RDATA     ] : " << ref.Resource_Data_Length << endl;
}

uint16_t CDNS_Manager::Get_DNS_Transaction_ID() const {
    return uint16_t(this->DNS_Transaction_ID);
}

uint16_t CDNS_Manager::Get_DNS_Question_Count() const {
    return uint16_t(this->DNS_Question_Count);
}

uint16_t CDNS_Manager::Get_DNS_Answer_Count() const {
    return uint16_t(this->DNS_Answer_Count);
}

uint16_t CDNS_Manager::Get_DNS_Name_Server_Count() const {
    return uint16_t(this->DNS_Name_Server_Count);
}

uint16_t CDNS_Manager::Get_DNS_Additional_Information_Record_Count() const {
    return uint16_t(this->DNS_Additional_Information_Record_Count);
}

uint16_t CDNS_Manager::Get_DNS_Payload_Lenght() const {
    return uint16_t(this->DNS_Payload_Length);
}

string CDNS_Manager::Get_DNS_Query_Or_Response() const {
    return this->DNS_Query_Or_Response ? string("[ Response ]") : string("[ Query ]");
}

string CDNS_Manager::Get_DNS_Operation_Code() const {
    switch(this->DNS_Operation_Code) {
    case 0:
        return string("[ Standard Query ]");
    case 1:
        return string("[ Reverse Query ]");
    case 2:
        return string("[ Status requirements for the server ]");
    case 3:
        return string("[ Notice ]");
    case 4:
        return string("[ Renewal ]");
    default:
        return string("");
    }
}

string CDNS_Manager::Get_DNS_Authoritative_Answer() const {
    return this->DNS_Authoritative_Answer ? string("[ Yes ]") : string("[ No ]");
}

string CDNS_Manager::Get_DNS_Truncated() const {
    return this->DNS_Truncated ? string("[ Yes ]") : string("[ No ]");
}

string CDNS_Manager::Get_DNS_Recursion_Desired() const {
    return this->DNS_Recursion_Desired ? string("[ Recursion Query ]") : string("[ Iterative Query ]");
}

string CDNS_Manager::Get_DNS_Recursion_Available() const {
    return this->DNS_Recursion_Available ? string("[ Yes ]") : string("[ No ]");
}

string CDNS_Manager::Get_DNS_Response_Code() const {
    switch(this->DNS_Response_Code) {
    case 0:
        return string("[ No Error ]");
    case 1:
        return string("[ Format Error ]");
    case 2:
        return string("[ Server Failure ]");
    case 3:
        return string("[ Not Exist Domain Name ]");
    default:
        return string("");
    }
}

string CDNS_Manager::Get_DNS_Data(uint8_t* EntryPtr, uint32_t len) const {
    char buff[2][256];
    string retPayload = "";
    string HexPayload = "";
    string CharPayload = "";

    int cnt = 0;
    for(int idx = 0; idx < len; idx++, cnt++){
        sprintf(buff[0], "%02X ", EntryPtr[idx]);
        HexPayload += string(buff[0]);
        
        switch(EntryPtr[idx]){
        case '\n':
            sprintf(buff[1], "\\n");
            break;
        case '\r':
            sprintf(buff[1], "\\r");
            break;
        case '\0':
            sprintf(buff[1], "\\0");
            break;
        case '\\':
            sprintf(buff[1], "\\");
        case '\t':
            sprintf(buff[1], "\\t");
            break;
        default:
            if((EntryPtr[idx] >= ' ') && (EntryPtr[idx] <= '~'))
                sprintf(buff[1], "%2c", EntryPtr[idx]);
            else
                sprintf(buff[1], "..");
            break;
        }
        CharPayload += string(buff[1]);
        
        if(cnt == 19){
            cnt = -1;
            retPayload += HexPayload + string("    ") + CharPayload + string("\n");
            HexPayload = "";
            CharPayload = "";
        }
    }

    if(HexPayload != ""){
        retPayload += HexPayload;
        for(int idx = 0; idx < (20 - cnt); idx++)
            retPayload += string("   ");

        retPayload += string("    ") + CharPayload + string("\n");
    }

    return retPayload;
}

void CDNS_Manager::Show_DNS_Header() const {
    cout << "[ DNS Transaction ID      ] : " << this->Get_DNS_Transaction_ID() << endl;
    cout << "[ DNS Question Count      ] : " << this->Get_DNS_Question_Count() << endl;
    cout << "[ DNS Answer Count        ] : " << this->Get_DNS_Answer_Count() << endl;
    cout << "[ DNS Name Server Count   ] : " << this->Get_DNS_Name_Server_Count() << endl;
    cout << "[ Add Info Rec Count      ] : " << this->Get_DNS_Additional_Information_Record_Count() << endl;

    cout << "[ DNS Query Or Response   ] : " << this->Get_DNS_Query_Or_Response() << endl;
    cout << "[ DNS Operation Code      ] : " << this->Get_DNS_Operation_Code() << endl;
    cout << "[ DNS Author Answer       ] : " << this->Get_DNS_Authoritative_Answer() << endl;
    cout << "[ DNS Truncated           ] : " << this->Get_DNS_Truncated() << endl;
    cout << "[ DNS Recursion Desired   ] : " << this->Get_DNS_Recursion_Desired() << endl;
    cout << "[ DNS Recursion Available ] : " << this->Get_DNS_Recursion_Available() << endl;
    cout << "[ DNS Response Code       ] : " << this->Get_DNS_Response_Code() << endl << endl;
}

void CDNS_Manager::ShowAppData() {
    int SectionSize = 0;
    this->Show_DNS_Header();
    this->Show_DNS_Query_Msg();
    if(this->Get_DNS_Query_Or_Response() == "[ Response ]")
        this->Show_DNS_Answer_Msg();
    else {
        for(int idx = 0; idx < Answer_Msg.size(); idx++)
            this->Show_Option_Msg(Answer_Msg[idx]);
    }
    
    cout<< "\n=========================================== [ DNS  Header ] ===========================================" << endl;
    cout << this->Get_DNS_Data((uint8_t*)this->DNS_Header_Entry, 12) << endl;
    cout<< "=========================================== [ DNS Payload ] ===========================================" << endl;
    cout << this->Get_DNS_Data(this->DNS_Payload_Entry, this->DNS_Payload_Length) << endl;
}
