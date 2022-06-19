#include "Telnet_Manager.h"
#include <iostream>
#include <cstring>
using namespace std;

CTelnet_Manager::CTelnet_Manager(CTCP_Manager& ref) : CTCP_Manager(ref) {
    if(bEmpty = (this->Get_TCP_Payload_Length() == 0) ? true : false)
        return;

    this->bCtrlMode = (this->pTCP_Payload_Entry[0] == 0xFF);

    if(bCtrlMode)
        Filtering_Option();
}

void CTelnet_Manager::Filtering_Option() {
    uint8_t* pCur = this->pTCP_Payload_Entry;
    uint16_t Len = this->Get_TCP_Payload_Length();

    for(uint16_t idx = 0; idx < Len; idx++) {
        if(pCur[idx] == 0xFF) {
            Option_Negotiation newOpt;

            newOpt.CmdCode = pCur[idx + 1];
            newOpt.OptCode = pCur[idx + 2];
            if(TelnetCmd(newOpt.CmdCode) == TelnetCmd::SubNegotiate) 
                idx += this->Filtering_SubOption(newOpt, &pCur[idx + 3]) + 3;
            else 
                idx += 2;
            
            this->Opt.push_back(newOpt);
        }
    }
}

uint8_t* CTelnet_Manager::Get_TELNET_Entry() {
    return Get_TCP_Payload_Entry();
}

ssize_t CTelnet_Manager::Get_TELNET_Len() {
    return Get_TCP_Payload_Length();
}

void CTelnet_Manager::ShowAppData() {
    if(bEmpty)
        return;

    if(bCtrlMode) {
        cout << ">> [ Control Message ] : " << Opt.size() << " EA" << endl;
        for(int idx = 0; idx < Opt.size(); idx++) {

            cout << ">> [ Command ]\n - " << GetCmdName(Opt[idx].CmdCode) << endl;
            cout << ">> [  Option ]\n - " << GetOptName(Opt[idx].OptCode) << endl;
            if(TelnetCmd(Opt[idx].CmdCode) == TelnetCmd::SubNegotiate) 
                cout << ">> [  Sub Option ]\n - " << Opt[idx].Value << endl;

            cout << endl;
        }
    }
    else {
        char* buf = new char[this->Get_TCP_Payload_Length() + 1];
        memset(buf, 0, this->Get_TCP_Payload_Length() + 1);
        memcpy(buf, this->pTCP_Payload_Entry, this->Get_TCP_Payload_Length());

        cout << ">> [ Data ]" << endl;
        cout << string(buf) << endl << endl;
        delete buf;
    }

    cout << ">> [ Payloads ]" << endl;
    cout << this->Get_TCP_Payload() << endl << endl;
}

uint16_t CTelnet_Manager::Filtering_SubOption(Option_Negotiation& ref, uint8_t* pCur) {
    uint16_t pos = 0;
    char buf[64] = { 0 };
    while(pCur[++pos] != 0xFF);

    switch(TelnetOpt(ref.OptCode)) {
    case TelnetOpt::Binary_Xmit:    //Allows transmission of binary data. 
        break;
    case TelnetOpt::Echo_Data:      //Causes server to echo back all keystrokes.
        break;
    case TelnetOpt::Reconnect:      //Reconnects to another TELNET host.
        break;
    case TelnetOpt::Suppress_GA:    //Disables Go Ahead! command. 
        break;
    case TelnetOpt::Message_Sz:     //Conveys approximate message size. 
        break;
    case TelnetOpt::Opt_Status:     //Lists status of options. 
        break;
    case TelnetOpt::Timing_Mark:    //Marks a data stream position for reference. 
        break;
    case TelnetOpt::RC_XmtEcho:     //Allows remote control of terminal printers.
        break;
    case TelnetOpt::Line_Width:     //Sets output line width. 
        break;
    case TelnetOpt::Page_Length:    //Sets page length in lines.
        break;
    case TelnetOpt::CR_Use:         //Determines handling of carriage returns. 
        break;
    case TelnetOpt::Horiz_Tabs:     //Sets horizontal tabs. 
        break;
    case TelnetOpt::Hor_Tab_Use:    //Determines handling of horizontal tabs. 
        break;
    case TelnetOpt::FF_Use:         //Determines handling of form feeds. 
        break;
    case TelnetOpt::Vert_Tabs:      //Sets vertical tabs.
        break;
    case TelnetOpt::Ver_Tab_Use:    //Determines handling of vertical tabs. 
        break;
    case TelnetOpt::Lf_Use:         //Determines handling of line feeds. 
        break;
    case TelnetOpt::Ext_ASCII:      //Defines extended ASCII characters. 
        break;
    case TelnetOpt::Logout:         //Allows for forced log-off.      
        break;
    case TelnetOpt::Byte_Macro:     //Defines byte macros. 
        break;
    case TelnetOpt::Data_Term:      //Allows subcommands for Data Entry to be sent.  
        break;
    case TelnetOpt::SUPDUP:         //Allows use of SUPDUP display protocol. 
        break;
    case TelnetOpt::SUPDUP_Outp:    //Allows sending of SUPDUP output. 
        break;
    case TelnetOpt::Send_Locate:    //Allows terminal location to be sent. 
        break;
    case TelnetOpt::Term_Type:      //Allows exchange of terminal type information.
        if(pCur[0]) 
            ref.Value += "Send your Terminal Type";
        else {
            ref.Value += "Here's my Terminal Type : ";
            if((pos - 1) > 1) {
                memcpy(buf, &pCur[1], (pos - 1));
                ref.Value += "[ " + string(buf) + " ]";
            }
        }
        break;
    case TelnetOpt::End_Record:     //Allows use of the End of record code(0xEF). 
        break;
    case TelnetOpt::TACACS_ID:      //User ID exchange used to avoid more than 1 log-in. 
        break;
    case TelnetOpt::Output_Mark:    //Allows banner markings to be sent on output. 
        break;
    case TelnetOpt::Term_Loc:       //A numeric ID used to identify terminals. 
        break;
    case TelnetOpt::Regime_3270:    //Allows emulation of 3270 family terminals. 
        break;
    case TelnetOpt::X_3_PAD:        //Allows use of X.3 protocol emulation. 
        break;
    case TelnetOpt::Window_Size:    //Conveys window size for emulation screen.
        sprintf(buf, "Width: %u,  ", pCur[0] << 8 | pCur[1]);
        ref.Value += buf;
        sprintf(buf, "Height: %u", pCur[2] << 8 | pCur[3]);
        ref.Value += buf;
        break;
    case TelnetOpt::Term_Speed:     //Conveys baud rate information. 
        break;
    case TelnetOpt::Remote_Flow:    //Provides flow control (XON, XOFF). 
        break;
    case TelnetOpt::Linemode:       //Provides linemode bulk character transactions. 
        break;
    case TelnetOpt::X_Display_Location:
        break;
    case TelnetOpt::Extended:       //options list  Extended options list. 
        break;
    default:
        ref.Value += "[ Option Data ] : "; 
        sprintf(buf, "%u", pCur[0]);
        ref.Value += buf;
        break;
    }    
    return pos + 1;
}

string CTelnet_Manager::GetCmdName(uint8_t CmdCode) const {
    switch(TelnetCmd(CmdCode)) {
    case TelnetCmd::End_subNeg:
        return string("[ End subNeg ]\n- End of option subnegotiation command.");
    case TelnetCmd::No_Operation:      
        return string("[ No Operation ]\n- No operation command.");
    case TelnetCmd::Data_Mark:     
        return string("[ Data Mark ]\n- End of urgent data stream.");
    case TelnetCmd::Break:      
        return string("[ Break ]\n- Operator pressed the Break key or the Attention key.");
    case TelnetCmd::Int_process:     
        return string("[ Int process ]\n- Interrupt current process.");
    case TelnetCmd::Abort_output:      
        return string("[ Abort output ]\n- Cancel output from current process.");
    case TelnetCmd::You_there:    
        return string("[ You there? ]\n- Request acknowledgment.");
    case TelnetCmd::Erase_char:     
        return string("[ Erase char ]\n- Request that operator erase the previous character.");
    case TelnetCmd::Erase_line:     
        return string("[ Erase line ]\n- Request that operator erase the previous line.");
    case TelnetCmd::Go_ahead:    
        return string("[ Go ahead! ]\n- End of input for half-duplex connections.");
    case TelnetCmd::SubNegotiate:      
        return string("[ SubNegotiate ]\n- Begin option subnegotiation.");
    case TelnetCmd::Will_Use:     
        return string("[ Will Use ]\n- Agreement to use the specified option.");
    case TelnetCmd::Wont_Use:      
        return string("[ Won't Use ]\n- Reject the proposed option.");
    case TelnetCmd::Start_use:     
        return string("[ Start use ]\n- Request to start using specified option.");
    case TelnetCmd::Stop_Use:   
        return string("[ Stop Use ]\n- Demand to stop using specified option.");
    case TelnetCmd::IAC:      
        return string("[ IAC ]\n- Interpret as command.");
    default:
        return string("[ Unknown ]\n- Maybe new environment.");
    }
}

string CTelnet_Manager::GetOptName(uint8_t OptCode) const {
    switch(TelnetOpt(OptCode)) {
    case TelnetOpt::Binary_Xmit: 
        return string("[ Binary Xmit ]\n- Allows transmission of binary data.");
    case TelnetOpt::Echo_Data: 
        return string("[ Echo Data ]\n- Causes server to echo back all keystrokes.");
    case TelnetOpt::Reconnect:      
        return string("[ Reconnect ]\n- Reconnects to another TELNET host.");
    case TelnetOpt::Suppress_GA:     
        return string("[ Suppress GA ]\n- Disables Go Ahead! command.");
    case TelnetOpt::Message_Sz:     
        return string("[ Message Sz ]\n- Conveys approximate message size.");
    case TelnetOpt::Opt_Status:      
        return string("[ Opt Status ]\n- Lists status of options.");
    case TelnetOpt::Timing_Mark:    
        return string("[ Timing Mark ]\n- Marks a data stream position for reference. ");
    case TelnetOpt::RC_XmtEcho:     
        return string("[ RC XmtEcho ]\n- Allows remote control of terminal printers.");
    case TelnetOpt::Line_Width:      
        return string("[ Line Width ]\n- Sets output line width.");
    case TelnetOpt::Page_Length:    
        return string("[ Page Length ]\n- Sets page length in lines.");
    case TelnetOpt::CR_Use:          
        return string("[ CR Use ]\n- Determines handling of carriage returns.");
    case TelnetOpt::Horiz_Tabs:      
        return string("[ Horiz Tabs ]\n- Sets horizontal tabs.");
    case TelnetOpt::Hor_Tab_Use:     
        return string("[ Hor Tab Use ]\n- Determines handling of horizontal tabs.");
    case TelnetOpt::FF_Use:          
        return string("[ FF Use ]\n- Determines handling of form feeds.");
    case TelnetOpt::Vert_Tabs:      
        return string("[ Vert Tabs ]\n- Sets vertical tabs.");
    case TelnetOpt::Ver_Tab_Use:     
        return string("[ Ver Tab Use ]\n- Determines handling of vertical tabs.");
    case TelnetOpt::Lf_Use:          
        return string("[ Lf Use ]\n- Determines handling of line feeds.");
    case TelnetOpt::Ext_ASCII:      
        return string("[ Ext ASCII ]\n- Defines extended ASCII characters.");
    case TelnetOpt::Logout:              
        return string("[ Logout ]\n- Allows for forced log-off.");
    case TelnetOpt::Byte_Macro:      
        return string("[ Byte Macro ] Defines byte macros.");
    case TelnetOpt::Data_Term:        
        return string("[ Data Term ]\n- Allows subcommands for Data Entry to be sent.");
    case TelnetOpt::SUPDUP:          
        return string("[ SUPDUP ]\n- Allows use of SUPDUP display protocol.");
    case TelnetOpt::SUPDUP_Outp:     
        return string("[ SUPDUP Outp ]\n- Allows sending of SUPDUP output.");
    case TelnetOpt::Send_Locate:     
        return string("[ Send Locate ]\n- Allows terminal location to be sent.");
    case TelnetOpt::Term_Type:       
        return string("[ Term Type ]\n- Allows exchange of terminal type information.");
    case TelnetOpt::End_Record:      
        return string("[ End Record ]\n- Allows use of the End of record code(0xEF).");
    case TelnetOpt::TACACS_ID:      
        return string("[ TACACS ID ]\n- User ID exchange used to avoid more than 1 log-in.");
    case TelnetOpt::Output_Mark:     
        return string("[ Output Mark ]\n- Allows banner markings to be sent on output.");
    case TelnetOpt::Term_Loc:        
        return string("[ Term Loc ]\n- A numeric ID used to identify terminals.");
    case TelnetOpt::Regime_3270:    
        return string("[ 3270 Regime ]\n- Allows emulation of 3270 family terminals.");
    case TelnetOpt::X_3_PAD:        
        return string("[ X.3 PAD ]\n- Allows use of X.3 protocol emulation. ");
    case TelnetOpt::Window_Size:    
        return string("[ Window Size ]\n- Conveys window size for emulation screen.");
    case TelnetOpt::Term_Speed:      
        return string("[ Term Speed ]\n- Conveys baud rate information.");
    case TelnetOpt::Remote_Flow:    
        return string("[ Remote Flow ]\n- Provides flow control (XON, XOFF).");
    case TelnetOpt::Linemode:        
        return string("[ Linemode ]\n- Provides linemode bulk character transactions.");
    case TelnetOpt::X_Display_Location:
        return string("[ X Display Location ]\n- Sender is willing to send the X display location in a subsequent sub-negotiation.");
    case TelnetOpt::Extended:       
        return string("[ Extended ]\n- options list  Extended options list.");
    default:
        return string("[ Unknown ]\n- Maybe new environment.");
    }
}
