#include "EthernetManager.h"
#include <stdint.h>
#include <iostream>
#include <string.h> 
#include <arpa/inet.h>

CEthernetManager::CEthernetManager(uint8_t* pPacketBuff, ssize_t PacketLength){
    struct ether_header* pEH = nullptr;

    memcpy(this->EtherHeaderBuff, pPacketBuff, PacketLength);       
    this->Length = PacketLength;                                       

    pEH = (struct ether_header*)this->EtherHeaderBuff;                 
    memcpy(this->DstMAC, pEH->ether_dhost, sizeof(pEH->ether_dhost));  
    memcpy(this->SrcMAC, pEH->ether_shost, sizeof(pEH->ether_shost));  
    this->EtherType = ntohs(pEH->ether_type);                        
    this->pEtherPayload = this->EtherHeaderBuff + sizeof(struct ether_header);
}

CEthernetManager::CEthernetManager(CEthernetManager& ref){
    struct ether_header* pEH = nullptr;

    memcpy(this->EtherHeaderBuff, ref.EtherHeaderBuff, ref.Length);    
    this->Length = ref.Length;                                         

    pEH = (struct ether_header*)this->EtherHeaderBuff;               
    memcpy(this->DstMAC, pEH->ether_dhost, sizeof(pEH->ether_dhost));  
    memcpy(this->SrcMAC, pEH->ether_shost, sizeof(pEH->ether_shost));   
    this->EtherType = ntohs(pEH->ether_type);                      
    this->pEtherPayload = ref.pEtherPayload;                        
}

string CEthernetManager::GetDstMAC() const{
    char buff[20];

    sprintf(buff, "%02X:%02X:%02X:%02X:%02X:%02X",
        this->DstMAC[0],
        this->DstMAC[1],
        this->DstMAC[2],
        this->DstMAC[3],
        this->DstMAC[4],
        this->DstMAC[5]
    );

    return string(buff);
}

string CEthernetManager::GetSrcMAC() const{
    char buff[20];

    sprintf(buff, "%02X:%02X:%02X:%02X:%02X:%02X",
        this->SrcMAC[0],
        this->SrcMAC[1],
        this->SrcMAC[2],
        this->SrcMAC[3],
        this->SrcMAC[4],
        this->SrcMAC[5]
    );

    return string(buff);
}

string CEthernetManager::GetEtherType() const{
    switch(this->EtherType){
    case ETHERTYPE_PUP:     /* Xerox PUP */
        return string("Xerox PUP");
    case ETHERTYPE_SPRITE:  /* Sprite */
        return string("Sprite");
    case ETHERTYPE_IP:      /* IPv4 */
        return string("IPv4");
    case ETHERTYPE_ARP:     /* Address resolution */
        return string("Address resolution");
    case ETHERTYPE_REVARP:  /* Reverse ARP */
        return string("Reverse ARP");
    case ETHERTYPE_AT:      /* AppleTalk protocol */
        return string("AppleTalk protocol");
    case ETHERTYPE_AARP:    /* AppleTalk ARP */
       return string("AppleTalk ARP");
    case ETHERTYPE_VLAN:    /* IEEE 802.1Q VLAN tagging */
        return string("IEEE 802.1Q VLAN tagging");
    case ETHERTYPE_IPX:     /* IPX */
        return string("IPX");
    case ETHERTYPE_IPV6:    /* IPv6 */
        return string("IPv6");
    case ETHERTYPE_LOOPBACK:/* used to test interfaces */
        return string("Loopback");
    default:                /* Unknown */
        return string("Unknown");
    }
}

uint8_t* CEthernetManager::GetEtherEntry() {
    return this->EtherHeaderBuff;
}

ssize_t CEthernetManager::GetEthHeaderLen() const {
    return 14;
}

ssize_t CEthernetManager::GetPacketLen() const {
    return int16_t(this->Length);
}

string CEthernetManager::WhoAmI() const{
    return string("CEthernetManager");
}


string CEthernetManager::GetRawData(uint8_t* pEntry, ssize_t Len) {
    const int ColCnt = 30;
    char buff[2][256];
    string retPayload = "";
    string HexPayload = "";
    string CharPayload = "";

    int cnt = 0;
    for(int idx = 0; idx < Len; idx++, cnt++){
        sprintf(buff[0], "%02X ", pEntry[idx]);
        HexPayload += string(buff[0]);

        switch(pEntry[idx]){
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
            break;
        case '\t':
            sprintf(buff[1], "\\t");
            break;
        default:
            if((pEntry[idx] >= '!') && (pEntry[idx] <= '~'))
                sprintf(buff[1], "%2c", pEntry[idx]);
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
