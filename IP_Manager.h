#ifndef __IP_MANAGER_H__
#define __IP_MANAGER_H__

#include "EthernetManager.h"
#include <stdint.h>

class CIP_Manager : public CEthernetManager {
protected:
    uint8_t*    pIP_Header_Entry;
    uint8_t     IP_Version;
    uint16_t    IP_Header_Length;
    uint8_t     IP_Type_Of_Service;
    uint16_t    IP_Total_Packet_Length;
    uint16_t    IP_Fragment_Identifier;
    uint16_t    IP_Fragmentation_Flags;
    uint16_t    IP_Fragmentation_Offset;
    uint8_t     IP_Time_To_Live;
    uint8_t     IP_Protocol_Identifier;
    uint16_t    IP_Header_Checksum;
    uint32_t    Src_IP_Address;
    uint32_t    Dst_IP_Address;
    uint16_t    IP_Option_Length;
    uint8_t*    pIP_Option;
    uint8_t*    pIP_Payload_Entry;
public:
    CIP_Manager(uint8_t* pPacketBuff, int16_t PacketLength);
    CIP_Manager(CIP_Manager& ref);
    CIP_Manager(CEthernetManager& EthernetManager);
    ~CIP_Manager();
private:
    void InitializeIP_Manager();
public:
    string          Get_IP_Version() const;
    uint8_t*        Get_IP_Header_Entry();
    uint8_t*        Get_IP_Payload_Entry();
    uint16_t        Get_IP_Header_Length() const;
    string          Get_IP_Type_Of_Service() const;
    uint16_t        Get_IP_Total_Packet_Length() const;
    uint16_t        Get_IP_Fragment_Identifier() const;
    string          Get_IP_Fragmentation_Flags() const;
    uint16_t        Get_IP_Fragmentation_Offset() const;
    uint16_t        Get_IP_Time_To_Live() const;
    string          Get_IP_Protocol_Identifier() const;
    uint16_t        Get_IP_Header_Checksum() const;
    uint16_t        Get_IP_Option_Length() const;
    uint16_t        Calulate_IP_CheckSum() const;
    bool            Is_IP_Validation() const;
public:
    virtual string WhoAmI() const;
    virtual uint16_t Get_Src_Port() const { return 0; }
    virtual uint16_t Get_Dst_Port() const { return 0; }
    virtual string Get_Src_IP_Address() const;
    virtual string Get_Dst_IP_Address() const;
    virtual string Get_IP_Protocol_ID_Summary() const;
};

#endif
