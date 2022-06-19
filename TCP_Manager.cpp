#include "TCP_Manager.h"
#include <netinet/tcp.h>
#include <arpa/inet.h>

CTCP_Manager::CTCP_Manager(uint8_t* pPacketBuff, int16_t PacketLength) : CIP_Manager(pPacketBuff, PacketLength) {
    this->InitializeTCP_Manager();
}

CTCP_Manager::CTCP_Manager(CIP_Manager& ref) : CIP_Manager(ref) {
    this->InitializeTCP_Manager();
}

void CTCP_Manager::InitializeTCP_Manager(){
    struct tcphdr* TCP_Head = (struct tcphdr*)this->pIP_Payload_Entry;

    this->pTCP_Header_Entry = this->pIP_Payload_Entry;
    this->Src_IP_Port = ntohs(TCP_Head->th_sport);
    this->Dst_IP_Port = ntohs(TCP_Head->th_dport);
  
    this->TCP_Sequence_Number = ntohl(TCP_Head->th_seq);
    this->TCP_Acknowledgement_Number = ntohl(TCP_Head->th_ack);
    this->TCP_Header_Length = TCP_Head->th_off * 4;
    this->TCP_Control_Flags = TCP_Head->th_flags;
    this->TCP_Window_Size = ntohs(TCP_Head->th_win);
    this->TCP_Checksum = ntohs(TCP_Head->th_sum);
    this->TCP_Urgent_Point = ntohs(TCP_Head->th_urp);
    this->TCP_Option_Length = this->TCP_Header_Length - 20;

    this->pTCP_Payload_Entry = this->pIP_Payload_Entry + this->TCP_Header_Length;

    //TCP 페이로드 세그먼트 크기 = (IP 헤더의 Total Length) - (IP 헤더의 Header Length) - (TCP 헤더의 Header Length)
    this->TCP_Payload_Length = (this->IP_Total_Packet_Length) - (this->IP_Header_Length) - (this->TCP_Header_Length);
}

uint8_t* CTCP_Manager::Get_TCP_Entry() {
    return this->Get_IP_Payload_Entry();
}

uint16_t CTCP_Manager::Get_Src_Port() const {
    return uint16_t(this->Src_IP_Port);
}

uint16_t CTCP_Manager::Get_Dst_Port() const {
    return uint16_t(this->Dst_IP_Port);
}

uint32_t CTCP_Manager::Get_TCP_Sequence_Number() const {
    return uint32_t(this->TCP_Sequence_Number);
}

uint32_t CTCP_Manager::Get_TCP_Acknowledgement_Number() const {
    return uint32_t(this->TCP_Acknowledgement_Number);
}

uint16_t CTCP_Manager::Get_TCP_Header_Length() const {
    return uint16_t(this->TCP_Header_Length);
}

string CTCP_Manager::Get_TCP_Control_Flags() const {
    string retMsg;

    if(this->TCP_Control_Flags & TH_FIN)
        retMsg += string("[FIN] ");

    if(this->TCP_Control_Flags & TH_SYN)
        retMsg += string("[SYN] ");

    if(this->TCP_Control_Flags & TH_RST)
        retMsg += string("[RST] ");

    if(this->TCP_Control_Flags & TH_PUSH)
        retMsg += string("[PUSH] ");

    if(this->TCP_Control_Flags & TH_ACK)
        retMsg += string("[ACK] ");

    if(this->TCP_Control_Flags & TH_URG)
        retMsg += string("[URG] ");

    return retMsg;
}

uint16_t CTCP_Manager::Get_TCP_Window_Size() const {
    return uint16_t(this->TCP_Window_Size);
}

uint16_t CTCP_Manager::Get_TCP_Checksum() const {
    return uint16_t(this->TCP_Checksum);
}

uint16_t CTCP_Manager::Get_TCP_Urgent_Point() const {
     return uint16_t(this->TCP_Urgent_Point);
}

uint16_t CTCP_Manager::Get_TCP_Option_Length() const {
    return uint16_t(this->TCP_Option_Length);
}

uint16_t CTCP_Manager::Get_TCP_Payload_Length() const {
    return uint16_t(this->TCP_Payload_Length);
}

uint8_t* CTCP_Manager::Get_TCP_Payload_Entry() {
    return this->Get_TCP_Entry() + this->Get_TCP_Header_Length();
}

string CTCP_Manager::Get_TCP_Payload() const {
    const int ColCnt = 30;
    char buff[2][256];
    string retPayload = "";
    string HexPayload = "";
    string CharPayload = "";

    int cnt = 0;
    for(int idx = 0; idx < this->TCP_Payload_Length; idx++, cnt++){
        sprintf(buff[0], "%02X ", this->pTCP_Payload_Entry[idx]);
        HexPayload += string(buff[0]);
        
        switch(this->pTCP_Payload_Entry[idx]){
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
            sprintf(buff[1], "\\ ");
        case '\t':
            sprintf(buff[1], "\\t");
            break;
        default:
            if((this->pTCP_Payload_Entry[idx] >= '!') && (this->pTCP_Payload_Entry[idx] <= '~'))
                sprintf(buff[1], "%2c", this->pTCP_Payload_Entry[idx]);
            else
                sprintf(buff[1], "..");
            break;
        }
        CharPayload += string(buff[1]);
        
        if(cnt == (ColCnt - 1)){
            cnt = -1;
            retPayload += HexPayload + string("    ") + CharPayload + string("\n");
            HexPayload = "";
            CharPayload = "";
        }
    }

    if(HexPayload != ""){
        retPayload += HexPayload;
        for(int idx = 0; idx < (ColCnt - cnt); idx++)
            retPayload += string("   ");

        retPayload += string("    ") + CharPayload + string("\n");
    }

    return retPayload;
}

string CTCP_Manager::WhoAmI() const {
    return string("CTCP_Manager");
}
