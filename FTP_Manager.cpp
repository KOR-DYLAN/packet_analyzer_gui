#include "FTP_Manager.h"
#include <iostream>
#include <cstring>
using namespace std;

CFTP_Manager::CFTP_Manager(CTCP_Manager& ref) : CTCP_Manager(ref) {
    bFTP_Operating_Mode = ((this->Src_IP_Port == 20) || (this->Dst_IP_Port == 20));
    bFTP_Connection_Mode = (this->Src_IP_Port == 21);

    bDirectories = true;
    for(int idx = 0; idx < TCP_Payload_Length; idx++) {
        if((pTCP_Payload_Entry[idx] < ' ') && (pTCP_Payload_Entry[idx] != '\n') && (pTCP_Payload_Entry[idx] != '\r')) {
            bDirectories = false;
            break;
        }
    }
    if(TCP_Payload_Length == 0)
        bDirectories = false;
        
    if(!bFTP_Operating_Mode || bDirectories) {
        char* buf = new char[TCP_Payload_Length + 1];
        memset(buf, 0, TCP_Payload_Length + 1);

        memcpy(buf, pTCP_Payload_Entry, TCP_Payload_Length);
        FTP_Message = string(buf); 

        size_t pos = FTP_Message.find('\r', 0);
        if(pos != string::npos)
            FTP_Message[pos] = '\0';

        pos = FTP_Message.find('\n', 0);
        if(pos != string::npos)
            FTP_Message[pos] = '\0';

        delete buf;
    }
}

uint8_t* CFTP_Manager::Get_FTP_Entry() {
    return Get_TCP_Payload_Entry();
}

ssize_t CFTP_Manager::Get_FTP_Len() {
    return Get_TCP_Payload_Length();
}

void CFTP_Manager::ShowAppData() {
    if(TCP_Payload_Length == 0)
        return;

    if(bFTP_Operating_Mode) {
        cout << "[ -------------- File Transport Mode -------------- ]" << endl;
        if(bDirectories) {
            cout << ">> [ Directory List ] " << endl;
            cout << FTP_Message;
        }
        else
            cout << Get_TCP_Payload();
    }
    else {
        if(bFTP_Connection_Mode) {
            cout << "[ -------------- Server Response -------------- ]" << endl;
            cout << ">> [ Original Message ]" << endl;
            cout << FTP_Message << endl;;
            cout << ">> [ Mean Of Reply Code ]" << endl;
            cout << GetReplyCodeDiscription() << endl << endl;
        }
        else {
            cout << "[ -------------- Client Request -------------- ]" << endl;
            cout << ">> [ Original Message ]" << endl;
            cout << FTP_Message << endl;
            cout << ">> [ Mean Of Command ]" << endl;
            cout << GetCommandDiscription() << endl << endl;
        }
       
    }

    cout << endl;
}

string CFTP_Manager::GetCommandDiscription() {
    char CommBuf[64];

    sscanf((char*)pTCP_Payload_Entry, "%s", CommBuf);
    string Command = string(CommBuf);

    if(Command == "ABOR")
        return string("Abort.");
    else if(Command == "ACCT")
        return string("Account.");
    else if(Command == "ADAT")
        return string("Authentication/Security Data.");
    else if(Command == "ALLO")
        return string("Allocate.");
    else if(Command == "APPE")
        return string("Append.");
    else if(Command == "AUTH")
        return string("Aythentication/Security Mechanism.");
    else if(Command == "CCC")
        return string("Clear Command Channel.");
    else if(Command == "CDUP")
        return string("Change to parent directory.");
    else if(Command == "CONF")
        return string("Confidentiality Protected Command.");
    else if(Command == "CWD")
        return string("Change working directory.");
    else if(Command == "DELE")
        return string("Delete.");
    else if(Command == "ENC")
        return string("Privacy Protected Command.");
    else if(Command == "EPRT")
        return string("Extended Data port.");
    else if(Command == "EPSV")
        return string("Extended Passive.");
    else if(Command == "FEAT")
        return string("Feature.");
    else if(Command == "HELP")
        return string("Help");
    else if(Command == "LANG")
        return string("Language negotiation.");
    else if(Command == "LIST")
        return string("List.");
    else if(Command == "LPRT")
        return string("Long data port.");
    else if(Command == "LPSV")
        return string("Long passive.");
    else if(Command == "MDTM")
        return string("File modification time.");
    else if(Command == "MIC")
        return string("Intergrity Protedted Command.");
    else if(Command == "MKD")
        return string("Make directory.");
    else if(Command == "MLSD")
        return string("Lists the contents of a directory if a directory is named.");
    else if(Command == "MLST")
        return string("Provides data about exactly the object named on its command line, and no others.");
    else if(Command == "MODE")
        return string("Sets the transfer mode (Stream, Block, or Compressed).");
    else if(Command == "NLST")
        return string("Returns a list of file names in a specified directory.");
    else if(Command == "NOOP")
        return string("No operation (dummy packet; used mostly on keepalives).");
    else if(Command == "OPTS")
        return string("Select options for a feature (for example OPTS UTF8 ON).");
    else if(Command == "PASS")
        return string("Authentication password.");
    else if(Command == "PASV")
        return string("Enter passive mode.");
    else if(Command == "PBSZ")
        return string("Protection Buffer Size.");
    else if(Command == "PORT")
        return string("Specifies an address and port to which the server should connect.");
    else if(Command == "PROT")
        return string("Data Channel Protection Level.");
    else if(Command == "PWD")
        return string("Print working directory. Returns the current directory of the host.");
    else if(Command == "QUIT.")
        return string("Disconnect.");
    else if(Command == "REIN")
        return string("Re initializes the connection.");
    else if(Command == "REST")
        return string("Restart transfer from the specified point.");
    else if(Command == "RETR")
        return string("Retrieve a copy of the file.");
    else if(Command == "RMD")
        return string("Remove a directory.");
    else if(Command == "RMDA")
        return string("Remove a directory tree.");
    else if(Command == "RNFR")
        return string("Rename from.");
    else if(Command == "RNTO")
        return string("Rename to.");
    else if(Command == "SITE")
        return string("Sends site specific commands to remote server (like SITE IDLE 60 or SITE UMASK 002).\nInspect SITE HELP output for complete list of supported commands.");
    else if(Command == "SIZE")
        return string("Return the size of a file.");
    else if(Command == "SMNT")
        return string("Mount file structure.");
    else if(Command == "SPSV")
        return string("Use single port passive mode.\n(only one TCP port number for both control connections and passive-mode data connections)");
    else if(Command == "STAT")
        return string("Returns the current status.");
    else if(Command == "STOR")
        return string("Accept the data and to store the data as a file at the server site");
    else if(Command == "STOU")
        return string("Store file uniquely.");
    else if(Command == "STRU")
        return string("Set file transfer structure.");
    else if(Command == "SYST")
        return string("Return system type.");
    else if(Command == "THMB")
        return string("Get a thumbnail of a remote image file.");
    else if(Command == "TYPE")
        return string("Sets the transfer mode (ASCII/Binary).");
    else if(Command == "USER")
        return string("Authentication username.");
    else if(Command == "XCUP")
        return string("Change to the parent of the current working directory.");
    else if(Command == "XMKD")
        return string("Make a directory.");
    else if(Command == "XPWD")
        return string("Print the current working directory.");
    else if(Command == "XRCP")
        return string("");
    else if(Command == "XRMD")
        return string("Remove the directory.");
    else if(Command == "XRSQ")
        return string("");
    else if(Command == "XSEM")
        return string("Send, mail if cannot.");
    else if(Command == "XSEN")
        return string("Send to terminal.");
    else
        return string("");
}

string CFTP_Manager::GetReplyCodeDiscription() {
    unsigned int ReplyCode;

    sscanf((char*)pTCP_Payload_Entry, "%u", &ReplyCode);

    switch(ReplyCode) {
    case 110:
        return string("Restart marker reply.");
    case 120:
        return string("Service ready in nnn minutes.");
    case 125:
        return string("Data connection already open; transfer starting.");
    case 150:
        return string("File status okay; about to open data connection.");
    case 200:
        return string("Command okay.");
    case 202:
        return string("Command not implemented, superfluous at this site.");
    case 211:
        return string("System status, or system help reply.");
    case 212:
        return string("Directory status.");
    case 213:
        return string("File status.");
    case 214:
        return string("Help message.");
    case 215:
        return string("NAME system type.");
    case 220:
        return string("Service ready for new user.");
    case 221:
        return string("Service closing control connetion.");
    case 225:
        return string("Data connection open; no transfer in progress.");
    case 226:
        return string("Closing data connection.");
    case 227:
        return string("Entering Passive Mode <h1, h2, h3, h4, p1, p2>.");
    case 228:
        return string("Entering Long Passive Mode Entered.");
    case 229:
        return string("Extended Passive Mode Entered.");
    case 230:
        return string("User logged in, proceed.");
    case 250:
        return string("Requested file action okay, completed.");
    case 257:
        return string("\"PATHNAME\" created.");
    case 331:
        return string("User name okay, need password.");
    case 332:
        return string("Need account for login.");
    case 350:
        return string("Requested file action pending further information.");
    case 421:
        return string("Service not available, closing control connection.");
    case 425:
        return string("Can't open data connection.");
    case 426:
        return string("Connection closed; transfer aborted.");
    case 450:
        return string("Requested file action not taken.");
    case 451:
        return string("Requested action aborted. Local error in processing.");
    case 452:
        return string("Requested action not taken.");
    case 500:
        return string("Syntax error, command unrecognized.");
    case 501:
        return string("Syntax rttot in parameters or arguments.");
    case 502:
        return string("Command not implemented.");
    case 503:
        return string("Bad sequence of commands.");
    case 504:
        return string("Command not implemented for that parameter.");
    case 521:
        return string("Supported address families are <af1, .., afn>.");
    case 530:
        return string("Not logged in.");
    case 532:
        return string("Need account for storing files.");
    case 550:
        return string("Requested action not taken.");
    case 551:
        return string("Requested action aborted. Page type unknown.");
    default:
        return string("Unknown...");
    }
}

