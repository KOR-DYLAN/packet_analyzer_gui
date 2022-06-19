#include "UDP_Manager.h"
#include <netinet/udp.h>
#include <arpa/inet.h>

CUDP_Manager::CUDP_Manager(uint8_t* pPacketBuff, int16_t PacketLength) : CIP_Manager(pPacketBuff, PacketLength) {
    this->InitializeUDP_Manager();
}
CUDP_Manager::CUDP_Manager(CIP_Manager& ref) : CIP_Manager(ref) {
    this->InitializeUDP_Manager();
}

void CUDP_Manager::InitializeUDP_Manager(){
    struct udphdr* pUDP_Head = (struct udphdr*)(pIP_Payload_Entry);

    this->pUDP_Header_Entry = pIP_Payload_Entry;
    this->Src_IP_Port = ntohs(pUDP_Head->uh_sport);
    this->Dst_IP_Port = ntohs(pUDP_Head->uh_dport);
    this->UDP_Length = ntohs(pUDP_Head->uh_ulen);
    this->UDP_Checksum = ntohs(pUDP_Head->uh_sum);
    this->pUDP_Payload_Entry = pIP_Payload_Entry + this->UDP_Header_Length;
    this->UDP_Payload_Length = this->UDP_Length - this->UDP_Header_Length;
}

ssize_t CUDP_Manager::Get_UDP_Header_Len() const {
    return 8;
}

uint8_t* CUDP_Manager::Get_UDP_Payload_Entry() {
    return this->Get_IP_Payload_Entry() + this->Get_UDP_Header_Len();
}

uint8_t* CUDP_Manager::Get_UDP_Entry() {
    return this->Get_IP_Payload_Entry();
}

uint16_t CUDP_Manager::Get_Src_Port() const {
    return uint16_t(this->Src_IP_Port);
}

uint16_t CUDP_Manager::Get_Dst_Port() const {
    return uint16_t(this->Dst_IP_Port);
}

uint16_t CUDP_Manager::Get_UDP_Payload_Length() const {
    return uint16_t(this->UDP_Payload_Length);
}

uint16_t CUDP_Manager::Get_UDP_Checksum() const {
    return uint16_t(this->UDP_Checksum);
}

string CUDP_Manager::Get_UDP_Payload() const {
    char buff[2][256];
    string retPayload = "";
    string HexPayload = "";
    string CharPayload = "";

    int cnt = 0;
    for(int idx = 0; idx < this->UDP_Payload_Length; idx++, cnt++){
        sprintf(buff[0], "%02X ", this->pUDP_Payload_Entry[idx]);
        HexPayload += string(buff[0]);
        
        switch(this->pUDP_Payload_Entry[idx]){
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
            if((this->pUDP_Payload_Entry[idx] >= ' ') && (this->pUDP_Payload_Entry[idx] <= '~'))
                sprintf(buff[1], "%2c", this->pUDP_Payload_Entry[idx]);
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

string CUDP_Manager::WhoAmI() const{
    return string("CUDP_Manager");
}
