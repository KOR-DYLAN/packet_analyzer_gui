#ifndef __TELNET_MANAGER_H__
#define __TELNET_MANAGER_H__

#include "TCP_Manager.h"
#include <vector>
using namespace std;

enum class TelnetCmd : uint8_t { 
   End_subNeg   = 240, //FO     End of option subnegotiation command. 
   No_Operation = 241, //F1     No operation command. 
   Data_Mark    = 242, //F2     End of urgent data stream. 
   Break        = 243, //F3     Operator pressed the Break key or the Attention key. 
   Int_process  = 244, //F4     Interrupt current process. 
   Abort_output = 245, //F5     Cancel output from current process. 
   You_there    = 246, //F6     Request acknowledgment. 
   Erase_char   = 247, //F7     Request that operator erase the previous character. 
   Erase_line   = 248, //F8     Request that operator erase the previous line. 
   Go_ahead     = 249, //F9     End of input for half-duplex connections.
   SubNegotiate = 250, //FA     Begin option subnegotiation. 
   Will_Use     = 251, //FB     Agreement to use the specified option. 
   Wont_Use     = 252, //FC     Reject the proposed option. 
   Start_use    = 253, //FD     Request to start using specified option. 
   Stop_Use     = 254, //FE     Demand to stop using specified option. 
   IAC          = 255, //FF     Interpret as command. 
};

enum class TelnetOpt : uint8_t { 
    Binary_Xmit     = 0,      //Allows transmission of binary data. 
    Echo_Data       = 1,      //Causes server to echo back all keystrokes.
    Reconnect       = 2,      //Reconnects to another TELNET host. 
    Suppress_GA     = 3,      //Disables Go Ahead! command. 
    Message_Sz      = 4,      //Conveys approximate message size. 
    Opt_Status      = 5,      //Lists status of options. 
    Timing_Mark     = 6,      //Marks a data stream position for reference. 
    RC_XmtEcho      = 7,      //Allows remote control of terminal printers. 
    Line_Width      = 8,      //Sets output line width. 
    Page_Length     = 9,      //Sets page length in lines. 
    CR_Use          = 10,     //Determines handling of carriage returns. 
    Horiz_Tabs      = 11,     //Sets horizontal tabs. 
    Hor_Tab_Use     = 12,     //Determines handling of horizontal tabs. 
    FF_Use          = 13,     //Determines handling of form feeds. 
    Vert_Tabs       = 14,     //Sets vertical tabs. 
    Ver_Tab_Use     = 15,     //Determines handling of vertical tabs. 
    Lf_Use          = 16,     //Determines handling of line feeds. 
    Ext_ASCII       = 17,     //Defines extended ASCII characters. 
    Logout          = 18,     //Allows for forced log-off. 
    Byte_Macro      = 19,     //Defines byte macros. 
    Data_Term       = 20,     //Allows subcommands for Data Entry to be sent. 
    SUPDUP          = 21,     //Allows use of SUPDUP display protocol. 
    SUPDUP_Outp     = 22,     //Allows sending of SUPDUP output. 
    Send_Locate     = 23,     //Allows terminal location to be sent. 
    Term_Type       = 24,     //Allows exchange of terminal type information. 
    End_Record      = 25,     //Allows use of the End of record code(0xEF). 
    TACACS_ID       = 26,     //User ID exchange used to avoid more than 1 log-in. 
    Output_Mark     = 27,     //Allows banner markings to be sent on output. 
    Term_Loc        = 28,     //A numeric ID used to identify terminals. 
    Regime_3270     = 29,     //Allows emulation of 3270 family terminals. 
    X_3_PAD         = 30,     //Allows use of X.3 protocol emulation. 
    Window_Size     = 31,     //Conveys window size for emulation screen. 
    Term_Speed      = 32,     //Conveys baud rate information. 
    Remote_Flow     = 33,     //Provides flow control (XON, XOFF). 
    Linemode        = 34,     //Provides linemode bulk character transactions. 
    X_Display_Location = 35,  // 
    Extended        = 255     //options list  Extended options list. 
};

typedef struct {
    uint8_t CmdCode;
    uint8_t OptCode;
    string Value;
} Option_Negotiation;

class CTelnet_Manager : public CTCP_Manager {
public:
    bool bEmpty;
    bool bCtrlMode;
    vector<Option_Negotiation> Opt;
public:
    uint8_t* Get_TELNET_Entry();
    ssize_t Get_TELNET_Len();
    void Filtering_Option();
    uint16_t Filtering_SubOption(Option_Negotiation& ref, uint8_t* pCur);
    string GetCmdName(uint8_t CmdCode) const;
    string GetOptName(uint8_t OptCode) const;
public:
    CTelnet_Manager(CTCP_Manager& ref);
public:
    virtual void ShowAppData();
};

#endif
