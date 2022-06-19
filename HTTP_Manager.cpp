#include "HTTP_Manager.h"
#include <iostream>
#include <string>
#include <cstring>
#include <sstream>
#include <cmath>

CHTTP_Manager::CHTTP_Manager(CTCP_Manager& ref) : CTCP_Manager(ref) {
    if(this->Get_TCP_Payload_Length() == 0) {
        this->ID = HTTP_Identifier::Empty;
        return;
    }
    this->OffsetCnt = 0;

    string token;
    stringstream ss((char*)this->pTCP_Payload_Entry);
    getline(ss, token, '\n');
    this->ID = this->Identifier(token);

    if((this->ID != HTTP_Identifier::Request_Header) && (this->ID != HTTP_Identifier::Response_Header))
        return;

    this->OffsetCnt = token.size() + 1;
    while(getline(ss, token, '\n')) {
        this->OffsetCnt += token.size() + 1;
        if(token[0] != '\r') {
            token[token.size() - 1] = '\0';
            HTTP_Header.push_back(token);
            continue;
        }
        break;
    }

    while(getline(ss, token, '\n')) {
        int Len = 0;

        if(token.size() < 2)
            continue;
        if((Len = HexString2Integer(token)) == -1)
            continue;

        Data_Length.push_back(Len);
    }
}

uint8_t* CHTTP_Manager::Get_HTTP_Entry() {
    return this->Get_TCP_Payload_Entry();
}

ssize_t CHTTP_Manager::Get_HTTP_Len() {
    return Get_TCP_Payload_Length();
}

int CHTTP_Manager::GetOffsetCnt() {
    return OffsetCnt;
}

HTTP_Identifier CHTTP_Manager::Identifier(string& ref) {
    stringstream ss(ref);
    string token;

    getline(ss, token, ' ');
    /* Identify Response. */
    if(token.compare(0, 4, "HTTP") == 0) {
        HTTP_First_Line = ref;
        return HTTP_Identifier::Response_Header;
    }

    /* Identify Request. */
    if(token.compare(0, 3, "GET") == 0) {
        HTTP_First_Line = ref;
        return HTTP_Identifier::Request_Header;
    }
    if(token.compare(0, 4, "POST") == 0) {
        HTTP_First_Line = ref;
        return HTTP_Identifier::Request_Header;
    }
    if(token.compare(0, 4, "HEAD") == 0) {
        HTTP_First_Line = ref;
        return HTTP_Identifier::Request_Header;
    }
    if(token.compare(0, 3, "PUT") == 0) {
        HTTP_First_Line = ref;
        return HTTP_Identifier::Request_Header;
    }
    if(token.compare(0, 6, "DELETE") == 0) {
        HTTP_First_Line = ref;
        return HTTP_Identifier::Request_Header;
    }
    if(token.compare(0, 5, "TRACE") == 0) {
        HTTP_First_Line = ref;
        return HTTP_Identifier::Request_Header;
    }
 
    return HTTP_Identifier::Data;
}

int CHTTP_Manager::HexString2Integer(string& ref) {
    int reVal = 0;
    
    for(int idx = 0; idx < (ref.size() - 1); idx++) {
        if(ref[idx] >= 'A' && ref[idx] <= 'F')
            reVal += pow(16, (ref.size() - 2) - idx) * (ref[idx] - 'A' + 10); 
        else if(ref[idx] >= 'a' && ref[idx] <= 'f')
            reVal += pow(16, (ref.size() - 2) - idx) * (ref[idx] - 'a' + 10);
        else if(ref[idx] >= '0' && ref[idx] <= '9')
            reVal += pow(16, (ref.size() - 2) - idx) * (ref[idx] - '0');
        else {
            reVal = 0;
            return -1;
        }
    }

    return reVal;
}

void CHTTP_Manager::ShowAppData() {
    switch(this->ID) {
    case HTTP_Identifier::Empty:
        return;
    case HTTP_Identifier::Request_Header:
        cout << "[ HTTP Request ]" << endl;
        cout << ">> " << HTTP_First_Line << endl;
        for(int idx = 0; idx < HTTP_Header.size(); idx++)
            cout << ">> " << HTTP_Header[idx] << endl;

        break;
    case HTTP_Identifier::Response_Header:
        cout << "[ HTTP Response ]" << endl;
        cout << ">> " << HTTP_First_Line << endl;
        for(int idx = 0; idx < HTTP_Header.size(); idx++)
            cout << ">> " << HTTP_Header[idx] << endl;     

        cout << endl;
        if(Data_Length.size() != 0) {
            cout << "[ Chunk Data : " << Data_Length.size() << " EA ]" << endl;
            for(int idx = 0; idx < Data_Length.size(); idx++)
                cout << ">> " << Data_Length[idx] << " byte" << endl;
        }

        cout << endl;
        cout << "[ Here is body or chunk data ]" << endl;
        cout << "Offset >> " << this->OffsetCnt << endl;
        cout << this->Get_HTTP_Data() << endl << endl;
        break;
    case HTTP_Identifier::Data:
        cout << "[ Maybe Data... ]" << endl;
        cout << this->Get_HTTP_Data() << endl;
        break;
    }
}

string CHTTP_Manager::Get_HTTP_Data() const {
    const int ColCnt = 30;
    char buff[2][256];
    string retPayload = "";
    string HexPayload = "";
    string CharPayload = "";

    int cnt = 0;
    cout << ">> Total : " << (this->TCP_Payload_Length - this->OffsetCnt) << " [ byte ]" << endl;
    for(int idx = this->OffsetCnt; idx < this->TCP_Payload_Length; idx++, cnt++){
        sprintf(buff[0], "%02X ", this->pTCP_Payload_Entry[idx]);
        HexPayload += string(buff[0]);
        
        switch(this->pTCP_Payload_Entry[idx]){
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
        case '\t':
            sprintf(buff[1], "\\t");
            break;
        default:
            if((this->pTCP_Payload_Entry[idx] >= ' ') && (this->pTCP_Payload_Entry[idx] <= '~'))
                sprintf(buff[1], "%2c", this->pTCP_Payload_Entry[idx]);
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
