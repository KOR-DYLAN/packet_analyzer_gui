#ifndef __UDP_MANAGER_H__
#define __UDP_MANAGER_H__

#include "IP_Manager.h"

class CUDP_Manager : public CIP_Manager{
protected:
    uint8_t*        pUDP_Header_Entry;
    uint16_t        Src_IP_Port;
    uint16_t        Dst_IP_Port;
    uint16_t        UDP_Length;
    uint16_t        UDP_Checksum;
    uint8_t*        pUDP_Payload_Entry;
    const uint16_t  UDP_Header_Length = 8;
    uint16_t        UDP_Payload_Length;
public:
    CUDP_Manager(uint8_t* pPacketBuff, int16_t PacketLength);
    CUDP_Manager(CIP_Manager& ref);
private:
    void InitializeUDP_Manager();
public:
    ssize_t     Get_UDP_Header_Len() const;
    uint8_t*    Get_UDP_Entry();
    uint8_t*    Get_UDP_Payload_Entry();
    uint16_t    Get_UDP_Payload_Length() const;
    uint16_t    Get_UDP_Checksum() const;
    string      Get_UDP_Payload() const;
public:
    virtual string WhoAmI() const;
    virtual void ShowAppData() {};
    virtual uint16_t Get_Src_Port() const;
    virtual uint16_t Get_Dst_Port() const;
};

#endif
