#ifndef __ETHERNET_MANAGER_H__
#define __ETHERNET_MANAGER_H__

#include <stdint.h>
#include <string>
#include <net/ethernet.h>
using namespace std;

class CEthernetManager{
protected:
    uint8_t     DstMAC[6];
    uint8_t     SrcMAC[6];
    uint16_t    EtherType;
    ssize_t     Length;
    uint8_t     EtherHeaderBuff[ETH_MAX_MTU];
    uint8_t*    pEtherPayload;
public:
    CEthernetManager(uint8_t* pPacketBuff, ssize_t PacketLength);
    CEthernetManager(CEthernetManager& ref);
public:
    uint8_t* GetEtherEntry();
    ssize_t GetEthHeaderLen() const;
    string GetDstMAC() const;
    string GetSrcMAC() const;
    string GetEtherType() const;
    ssize_t GetPacketLen() const;
public:
    virtual string WhoAmI() const;
    virtual uint16_t Get_Src_Port() const { return 0; }
    virtual uint16_t Get_Dst_Port() const { return 0; }
    virtual string Get_Src_IP_Address() const { return ""; }
    virtual string Get_Dst_IP_Address() const { return ""; }
    virtual string Get_IP_Protocol_ID_Summary() const { return ""; }
    static string GetRawData(uint8_t* pEntry, ssize_t Len);
};

#endif
