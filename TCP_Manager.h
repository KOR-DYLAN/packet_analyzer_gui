#ifndef __TCP_MANAGER_H__
#define __TCP_MANAGER_H__

#include "IP_Manager.h"

class CTCP_Manager : public CIP_Manager {
protected:
    uint8_t*        pTCP_Header_Entry;
    uint16_t        Src_IP_Port;
    uint16_t        Dst_IP_Port;
  
    uint32_t        TCP_Sequence_Number;
    uint32_t        TCP_Acknowledgement_Number;
    uint8_t         TCP_Header_Length;
    uint8_t         TCP_Control_Flags;
    uint16_t        TCP_Window_Size;
    uint16_t        TCP_Checksum;
    uint16_t        TCP_Urgent_Point;

    uint8_t         TCP_Option_Length;
    uint8_t*        pTCP_Payload_Entry;
    uint16_t        TCP_Payload_Length;
public:
    CTCP_Manager(uint8_t* pPacketBuff, int16_t PacketLength);
    CTCP_Manager(CIP_Manager& ref);
private:
    void InitializeTCP_Manager();
public:
    uint8_t*    Get_TCP_Entry();
    uint32_t    Get_TCP_Sequence_Number() const;
    uint32_t    Get_TCP_Acknowledgement_Number() const;
    uint16_t    Get_TCP_Header_Length() const;
    string      Get_TCP_Control_Flags() const;
    uint16_t    Get_TCP_Window_Size() const;
    uint16_t    Get_TCP_Checksum() const;
    uint16_t    Get_TCP_Urgent_Point() const;
    uint16_t    Get_TCP_Option_Length() const;
    uint16_t    Get_TCP_Payload_Length() const;
    string      Get_TCP_Payload() const;
    uint8_t*    Get_TCP_Payload_Entry();
public:
    virtual string WhoAmI() const;
    virtual void ShowAppData() {};
    virtual uint16_t Get_Src_Port() const;
    virtual uint16_t Get_Dst_Port() const;
};

#endif
