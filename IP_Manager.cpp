#include "IP_Manager.h"
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <string.h>

struct iphdr* s;

CIP_Manager::CIP_Manager(uint8_t* pPacketBuff, int16_t PacketLength) : CEthernetManager(pPacketBuff, PacketLength) {
    this->InitializeIP_Manager();
}

CIP_Manager::CIP_Manager(CIP_Manager& ref) : CEthernetManager(ref) {
    this->InitializeIP_Manager();
}

CIP_Manager::CIP_Manager(CEthernetManager& EthernetManager) : CEthernetManager(EthernetManager) {
    this->InitializeIP_Manager();
}

CIP_Manager::~CIP_Manager() {
    delete[] this->pIP_Option;
}

void CIP_Manager::InitializeIP_Manager(){
    struct iphdr* pIpH = (struct iphdr*)pEtherPayload;
    
    this->pIP_Header_Entry          = pEtherPayload;
    this->IP_Version                = pIpH->version;
    this->IP_Header_Length          = uint16_t(pIpH->ihl) * 4;
    this->IP_Type_Of_Service        = pIpH->tos;
    this->IP_Total_Packet_Length    = ntohs(pIpH->tot_len);
    this->IP_Fragment_Identifier    = ntohs(pIpH->id);
    this->IP_Fragmentation_Flags    = (ntohs(pIpH->frag_off) & 0b1110000000000000);
    this->IP_Fragmentation_Offset   = (ntohs(pIpH->frag_off) & IP_OFFMASK);
    this->IP_Time_To_Live           = pIpH->ttl;
    this->IP_Protocol_Identifier    = pIpH->protocol;
    this->IP_Header_Checksum        = ntohs(pIpH->check);
    this->Src_IP_Address            = pIpH->saddr;
    this->Dst_IP_Address            = pIpH->daddr;
    this->IP_Option_Length          = this->IP_Header_Length - 20;

    if(this->IP_Option_Length > 0){
        this->pIP_Option            = new uint8_t[this->IP_Option_Length];
        memcpy(this->pIP_Option, (pIpH + sizeof(struct iphdr)), this->IP_Option_Length);
    }
    else
        this->pIP_Option            = nullptr;
      
    this->pIP_Payload_Entry = pEtherPayload + sizeof(struct iphdr) + this->IP_Option_Length;
}

string CIP_Manager::Get_IP_Version() const{
    switch(this->IP_Version){
    case 4:
        return string("Internet Protocol Version 4");
    case 5:
        return string("ST Datagram Mode");
    case 6:
        return string("Internet Protocol version 6");
    case 7:
        return string("TP/IX: The Next Internet");
    case 8:
        return string("The P Internet Protocol");
    case 9:
        return string("TUBA");
    default:
        return string("Unknown");
    }
}

uint8_t* CIP_Manager::Get_IP_Header_Entry(){
    return this->EtherHeaderBuff + sizeof(struct ether_header);
}

uint8_t* CIP_Manager::Get_IP_Payload_Entry() {
    return this->Get_IP_Header_Entry() + this->Get_IP_Header_Length();
}

uint16_t CIP_Manager::Get_IP_Header_Length() const{
    return uint8_t(this->IP_Header_Length);
}

string CIP_Manager::Get_IP_Type_Of_Service() const{
    string retMsg;

    if(this->IP_Type_Of_Service == 0)
        return string("[Normal] ");
    
    if(this->IP_Type_Of_Service & 0x01)
        retMsg += string("[Min Cost] ");

    if(this->IP_Type_Of_Service & 0x02)
        retMsg += string("[Max Reliability] ");

    if(this->IP_Type_Of_Service & 0x04)
        retMsg += string("[Max Throughtout] ");
    
    if(this->IP_Type_Of_Service & 0x08)
        retMsg += string("[Min Delay] ");

    if(this->IP_Type_Of_Service & 0x10)
        retMsg += string("[Max Security] ");
    
    return retMsg;
}

uint16_t CIP_Manager::Get_IP_Total_Packet_Length() const{
    return uint16_t(this->IP_Total_Packet_Length);
}

uint16_t CIP_Manager::Get_IP_Fragment_Identifier() const{
    return uint16_t(this->IP_Fragment_Identifier);
}

string CIP_Manager::Get_IP_Fragmentation_Flags() const{
    string retMsg;
    char buf[10];
    sprintf(buf, "[0x%04X] ", this->IP_Fragmentation_Flags );

    retMsg += string(buf);
    if(!(this->IP_Fragmentation_Flags & IP_DF))
        retMsg += string("[May Fragment] ");

    if(this->IP_Fragmentation_Flags & IP_MF)
        retMsg += string("[More Fragments] ");
    
    return retMsg;
}

uint16_t CIP_Manager::Get_IP_Fragmentation_Offset() const{
    return uint16_t(this->IP_Fragmentation_Offset) * sizeof(uint8_t);
}

uint16_t CIP_Manager::Get_IP_Time_To_Live() const{
    return uint16_t(this->IP_Time_To_Live);
}

string CIP_Manager::Get_IP_Protocol_Identifier() const{
    switch(this->IP_Protocol_Identifier){
    case IPPROTO_IP:       /* Dummy protocol for TCP.  */
        return string("[Dummy protocol for TCP]");   
    case IPPROTO_ICMP:	   /* Internet Control Message Protocol.  */
        return string("[Internet Control Message Protocol]");  
    case IPPROTO_IGMP:	   /* Internet Group Management Protocol. */
        return string("[Internet Group Management Protocol]");  
    case IPPROTO_IPIP:	   /* IPIP tunnels (older KA9Q tunnels use 94).  */
        return string("[IPIP tunnels]");  
    case IPPROTO_TCP:	   /* Transmission Control Protocol.  */
        return string("[Transmission Control Protocol]");  
    case IPPROTO_EGP:	   /* Exterior Gateway Protocol.  */
        return string("[Exterior Gateway Protocol]");  
    case IPPROTO_PUP:	   /* PUP protocol.  */
        return string("[PUP protocol]");  
    case IPPROTO_UDP:	   /* User Datagram Protocol.  */
        return string("[User Datagram Protocol]");  
    case IPPROTO_IDP:	   /* XNS IDP protocol.  */
        return string("[XNS IDP protocol]");  
    case IPPROTO_TP:	   /* SO Transport Protocol Class 4.  */
        return string("[SO Transport Protocol Class 4]");  
    case IPPROTO_DCCP:	   /* Datagram Congestion Control Protocol.  */
        return string("[Datagram Congestion Control Protocol]");  
    case IPPROTO_IPV6:     /* IPv6 header.  */
        return string("[IPv6 header]");  
    case IPPROTO_RSVP:	   /* Reservation Protocol.  */
        return string("[Reservation Protocol]");  
    case IPPROTO_GRE:	   /* General Routing Encapsulation.  */
        return string("[General Routing Encapsulation]");  
    case IPPROTO_ESP:      /* encapsulating security payload.  */
        return string("[encapsulating security payload]");  
    case IPPROTO_AH:       /* authentication header.  */
        return string("[authentication header]");  
    case IPPROTO_MTP:	   /* Multicast Transport Protocol.  */
        return string("[Multicast Transport Protocol]");  
    case IPPROTO_BEETPH:   /* IP option pseudo header for BEET.  */
        return string("[IP option pseudo header for BEET]");  
    case IPPROTO_ENCAP:	   /* Encapsulation Header.  */
        return string("[Encapsulation Header]");  
    case IPPROTO_PIM:	   /* Protocol Independent Multicast.  */
        return string("[Protocol Independent Multicast]");  
    case IPPROTO_COMP:	   /* Compression Header Protocol.  */
        return string("[Compression Header Protocol]");  
    case IPPROTO_SCTP:	   /* Stream Control Transmission Protocol.  */
        return string("[Stream Control Transmission Protocol]");  
    case IPPROTO_UDPLITE:  /* UDP-Lite protocol.  */
        return string("[UDP-Lite protocol]");  
    case IPPROTO_MPLS:     /* MPLS in IP.  */
        return string("[MPLS in IP]");  
    case IPPROTO_RAW:	   /* Raw IP packets.  */
        return string("[Raw IP packets]");  
    default:
        return string("[Unknown]"); 
    }
}

uint16_t CIP_Manager::Get_IP_Header_Checksum() const{
    return uint16_t(IP_Header_Checksum);
}

string CIP_Manager::Get_Src_IP_Address() const{
    char addr[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, (const void*)&this->Src_IP_Address, addr, sizeof(addr));

    return string(addr);
}

string CIP_Manager::Get_Dst_IP_Address() const{
    char addr[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, (const void*)&this->Dst_IP_Address, addr, sizeof(addr));

    return string(addr);
}

uint16_t CIP_Manager::Get_IP_Option_Length() const{
    return uint16_t(IP_Option_Length);
}

uint16_t CIP_Manager::Calulate_IP_CheckSum() const{
    const ushort* buff = (ushort*)this->pIP_Header_Entry;
    const ushort len = (this->IP_Header_Length / 2);

    ulong CheckSum = 0;

    for(ushort idx = 0; idx < len; idx++){
        if(idx == 5)
            continue;

        CheckSum += ntohs(buff[idx]);
    }
    
    CheckSum = (CheckSum & 0xFFFF) + (CheckSum >> 16);

    return (uint16_t)CheckSum;
}

bool CIP_Manager::Is_IP_Validation() const{
    const uint16_t Check = this->Calulate_IP_CheckSum() + this->Get_IP_Header_Checksum();

    return (Check == 0xFFFF);
}

string CIP_Manager::WhoAmI() const{
    return string("CIP_Manager");
}

string CIP_Manager::Get_IP_Protocol_ID_Summary() const {
    switch(this->IP_Protocol_Identifier){
    case IPPROTO_IP:       /* Dummy protocol for TCP.  */
        return string("TCP Dummy");
    case IPPROTO_ICMP:	   /* Internet Control Message Protocol.  */
        return string("ICMP");
    case IPPROTO_IGMP:	   /* Internet Group Management Protocol. */
        return string("IGMP");
    case IPPROTO_IPIP:	   /* IPIP tunnels (older KA9Q tunnels use 94).  */
        return string("IPIP");
    case IPPROTO_TCP:	   /* Transmission Control Protocol.  */
        return string("TCP");
    case IPPROTO_EGP:	   /* Exterior Gateway Protocol.  */
        return string("EGP");
    case IPPROTO_PUP:	   /* PUP protocol.  */
        return string("PUP");
    case IPPROTO_UDP:	   /* User Datagram Protocol.  */
        return string("UDP");
    case IPPROTO_IDP:	   /* XNS IDP protocol.  */
        return string("XNS");
    case IPPROTO_TP:	   /* SO Transport Protocol Class 4.  */
        return string("SO Class 4");
    case IPPROTO_DCCP:	   /* Datagram Congestion Control Protocol.  */
        return string("DCCP");
    case IPPROTO_IPV6:     /* IPv6 header.  */
        return string("IPv6");
    case IPPROTO_RSVP:	   /* Reservation Protocol.  */
        return string("Reservation");
    case IPPROTO_GRE:	   /* General Routing Encapsulation.  */
        return string("GRE");
    case IPPROTO_ESP:      /* encapsulating security payload.  */
        return string("ESP");
    case IPPROTO_AH:       /* authentication header.  */
        return string("AH");
    case IPPROTO_MTP:	   /* Multicast Transport Protocol.  */
        return string("MTP");
    case IPPROTO_BEETPH:   /* IP option pseudo header for BEET.  */
        return string("BEET Option");
    case IPPROTO_ENCAP:	   /* Encapsulation Header.  */
        return string("EH");
    case IPPROTO_PIM:	   /* Protocol Independent Multicast.  */
        return string("Multicast");
    case IPPROTO_COMP:	   /* Compression Header Protocol.  */
        return string("CHP");
    case IPPROTO_SCTP:	   /* Stream Control Transmission Protocol.  */
        return string("SCTP");
    case IPPROTO_UDPLITE:  /* UDP-Lite protocol.  */
        return string("Lite UDP");
    case IPPROTO_MPLS:     /* MPLS in IP.  */
        return string("MPLS");
    case IPPROTO_RAW:	   /* Raw IP packets.  */
        return string("Raw IP");
    default:
        return string("Unknown");
    }
}
