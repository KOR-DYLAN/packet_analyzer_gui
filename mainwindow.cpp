#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "promiscdialog.h"
#include "information.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <dirent.h>
#include <sstream>

#define FiledWidth 30

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    bStart = false;

    setWindowIcon(QIcon(":/new/prefix1/Icon.png"));
    EditorChecker = "[ Machining Data ] Empty";

    /* Redirection UI Component Pointer */
    this->SummaryTable[static_cast<int>(TYPE::ALL)] = ui->All_Table;
    this->SummaryTable[static_cast<int>(TYPE::TCP)] = ui->TCP_Table;
    this->SummaryTable[static_cast<int>(TYPE::UDP)] = ui->UDP_Table;
    this->SummaryTable[static_cast<int>(TYPE::HTTP)] = ui->HTTP_Table;
    this->SummaryTable[static_cast<int>(TYPE::FTP)] = ui->FTP_Table;
    this->SummaryTable[static_cast<int>(TYPE::TELNET)] = ui->TELNET_Table;
    this->SummaryTable[static_cast<int>(TYPE::DNS)] = ui->DNS_Table;
    this->DetailTree = ui->DetailTree;

    /* Create & Register Model Items */
    for(int idx = 0; idx < static_cast<int>(TYPE::COUNT); idx++) {
        this->TableModel[idx] = new QStandardItemModel(this);

        this->TableModel[idx]->insertColumns(0, static_cast<int>(CAT::COUNT));
        this->TableModel[idx]->setHeaderData(static_cast<int>(CAT::SRC_IP), Qt::Horizontal, "Src IP");
        this->TableModel[idx]->setHeaderData(static_cast<int>(CAT::DST_IP), Qt::Horizontal, "Dst IP");
        this->TableModel[idx]->setHeaderData(static_cast<int>(CAT::SRC_PORT), Qt::Horizontal, "Src Port");
        this->TableModel[idx]->setHeaderData(static_cast<int>(CAT::DST_PORT), Qt::Horizontal, "Dst Port");
        this->TableModel[idx]->setHeaderData(static_cast<int>(CAT::SIZE), Qt::Horizontal, "Size");
        this->TableModel[idx]->setHeaderData(static_cast<int>(CAT::TRANSPORT), Qt::Horizontal, "Transport");

        this->SummaryTable[idx]->setModel(TableModel[idx]);
    }
    DetailTree->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    showMaximized();

    /* Create Raw Socket */
    RawSocketFd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    // Create Epoll Instance.
    epollFd = epoll_create(1);

    // Set Non-Blocking Socket.
    int flag = fcntl(RawSocketFd, F_GETFL, 0);
    fcntl(RawSocketFd, F_SETFL, flag | O_NONBLOCK);

    // Set Epoll Control.
    epollEvent.events = EPOLLIN;
    epollEvent.data.fd = RawSocketFd;
    epoll_ctl(epollFd, EPOLL_CTL_ADD, RawSocketFd, &epollEvent);

    // Read NIC List
    Read_NIC_List();

    /* Register Idle Loop */
    dispatcher = QAbstractEventDispatcher::instance();
    connect(dispatcher, SIGNAL(aboutToBlock()), SLOT(aboutToBlock()));
    //connect(dispatcher, SIGNAL(awake()), SLOT(awake()));

    /* Connect Program Info */
    connect(ui->actionProgram_Information, SIGNAL(triggered()), SLOT(on_Program_Information_Menu_clicked()));
}

MainWindow::~MainWindow()
{
    ::close(RawSocketFd);
    delete ui;
}

void MainWindow::resizeEvent(QResizeEvent* event) {
    QMainWindow::resizeEvent(event);
    ResizeHandler();
}

void MainWindow::on_tabWidget_currentChanged(int index) {
    ResizeHandler();
}

void MainWindow::ResizeHandler() {
    const int ColumnCnt = static_cast<int>(CAT::COUNT);

    for(int type = 0; type < static_cast<int>(TYPE::COUNT); type++) {
        int Width = SummaryTable[type]->width();
        SummaryTable[type]->setColumnWidth(static_cast<int>(CAT::SRC_IP), Width * 4 / 20);
        SummaryTable[type]->setColumnWidth(static_cast<int>(CAT::DST_IP), Width * 4 / 20);
        SummaryTable[type]->setColumnWidth(static_cast<int>(CAT::SRC_PORT), Width * 3 / 20);
        SummaryTable[type]->setColumnWidth(static_cast<int>(CAT::DST_PORT), Width * 3 / 20);
        SummaryTable[type]->setColumnWidth(static_cast<int>(CAT::SIZE), Width * 3 / 20);
        SummaryTable[type]->setColumnWidth(static_cast<int>(CAT::TRANSPORT), Width * 3 / 20);
    }
}

void MainWindow::aboutToBlock() {
    uint8_t buf[ETH_MAX_MTU];

    // Check Promisc Status.
    Check_Promisc();

    int retVal = epoll_wait(epollFd, &EventList, 1, 1);
    if(retVal == EINTR) {
        return;
    }

    if(EventList.data.fd != RawSocketFd) {
        return;
    }

    memset(buf, 0, ETH_MAX_MTU);
    ssize_t recvLen = read(RawSocketFd, buf, sizeof(buf));
    if(recvLen <= 0) {
        return;
    }

    if(bStart != true) {
        return;
    }

    this->CaptureLoop(buf, recvLen);
}

void MainWindow::CaptureLoop(uint8_t buf[], ssize_t recvLen) {
    // Unpack Ether packet.
    CEthernetManager Ether_Packet(buf, recvLen);

    if(Ether_Packet.GetEtherType() != "IPv4")
        return;

    // Unpack IP packet.
    CIP_Manager IP_Packet(Ether_Packet);
    // Loopback Filtering.
    if((IP_Packet.Get_Src_IP_Address() == "127.0.0.1") || (IP_Packet.Get_Dst_IP_Address() == "127.0.0.1"))
        return;

    if((IP_Packet.Get_Src_IP_Address() == "") || (IP_Packet.Get_Dst_IP_Address() == ""))
        return;

    if(IP_Packet.Get_IP_Protocol_Identifier() == "[User Datagram Protocol]") {
        // Unpack UDP packet.
        shared_ptr<CUDP_Manager> UDP_Packet(new CUDP_Manager(IP_Packet));
        if(IsProtocol(TYPE::DNS, UDP_Packet->Get_Src_Port()) || IsProtocol(TYPE::DNS, UDP_Packet->Get_Dst_Port())) {
            shared_ptr<CDNS_Manager> DNS_Packet(new CDNS_Manager(*UDP_Packet.get()));

            DNS_Ptrs.push_back(DNS_Packet);
            this->UpdateDNS_Form();
        }

        UDP_Ptrs.push_back(UDP_Packet);
        PacketObjects.push_back(UDP_Packet);

        this->UpdateUDP_Form();
        this->UpdateALL_Form();
    }
    else if(IP_Packet.Get_IP_Protocol_Identifier() == "[Transmission Control Protocol]") {
        // Unpack TCP packet.
        shared_ptr<CTCP_Manager> TCP_Packet(new CTCP_Manager(IP_Packet));
        if(IsProtocol(TYPE::HTTP, TCP_Packet->Get_Src_Port()) || IsProtocol(TYPE::HTTP, TCP_Packet->Get_Dst_Port())) {
            shared_ptr<CHTTP_Manager> HTTP_Packet(new CHTTP_Manager(*TCP_Packet.get()));

            HTTP_Ptrs.push_back(HTTP_Packet);
            this->UpdateHTTP_Form();
        }
        else if(IsProtocol(TYPE::FTP, TCP_Packet->Get_Src_Port()) || IsProtocol(TYPE::FTP, TCP_Packet->Get_Dst_Port())) {
            shared_ptr<CFTP_Manager> FTP_Packet(new CFTP_Manager(*TCP_Packet.get()));

            FTP_Ptrs.push_back(FTP_Packet);
            this->UpdateFTP_Form();
        }
        else if(IsProtocol(TYPE::TELNET, TCP_Packet->Get_Src_Port()) || IsProtocol(TYPE::TELNET, TCP_Packet->Get_Dst_Port())) {
            shared_ptr<CTelnet_Manager> TELNET_Packet(new CTelnet_Manager(*TCP_Packet.get()));

            TELNET_Ptrs.push_back(TELNET_Packet);
            this->UpdateTELNET_Form();
        }

        TCP_Ptrs.push_back(TCP_Packet);
        PacketObjects.push_back(TCP_Packet);

        this->UpdateTCP_Form();
        this->UpdateALL_Form();
    }
}

bool MainWindow::IsProtocol(TYPE ID, int port) {
    switch(port){
    case 23:
        return (ID == TYPE::TELNET) ? true : false;
    case 20: case 21:
        return (ID == TYPE::FTP) ? true : false;
    case 80:
        return (ID == TYPE::HTTP) ? true : false;
    case 53:
        return (ID == TYPE::DNS) ? true : false;
    default:
        return false;
    }
}

void MainWindow::UpdateSummaryTable(TYPE ID, int index, CEthernetManager* src) {
    TableModel[static_cast<int>(ID)]->
            setItem(index, static_cast<int>(CAT::SRC_IP), new QStandardItem(src->Get_Src_IP_Address().c_str()));
    TableModel[static_cast<int>(ID)]->
            setItem(index, static_cast<int>(CAT::DST_IP), new QStandardItem(src->Get_Dst_IP_Address().c_str()));
    TableModel[static_cast<int>(ID)]->
            setItem(index, static_cast<int>(CAT::SRC_PORT), new QStandardItem(QString::number(src->Get_Src_Port())));
    TableModel[static_cast<int>(ID)]->
            setItem(index, static_cast<int>(CAT::DST_PORT), new QStandardItem(QString::number(src->Get_Dst_Port())));
    TableModel[static_cast<int>(ID)]->
            setItem(index, static_cast<int>(CAT::SIZE), new QStandardItem(QString::number(src->GetPacketLen())));
    TableModel[static_cast<int>(ID)]->
            setItem(index, static_cast<int>(CAT::TRANSPORT), new QStandardItem(src->Get_IP_Protocol_ID_Summary().c_str()));
}

void MainWindow::UpdateALL_Form() {
    int row = TableModel[static_cast<int>(TYPE::ALL)]->rowCount();

    UpdateSummaryTable(TYPE::ALL, row, PacketObjects[row].get());

    QStandardItemModel* newRootItem = new QStandardItemModel(this);
    newRootItem->insertColumns(0, 1);
    newRootItem->setHeaderData(0, Qt::Horizontal, "Packet analysis contents");
    this->UpdateETH_Tree(newRootItem, PacketObjects[row].get());
    this->UpdateIP_Tree(newRootItem, dynamic_cast<CIP_Manager*>(PacketObjects[row].get()));

    if(PacketObjects[row]->Get_IP_Protocol_ID_Summary() == "TCP"){
        this->UpdateTCP_Tree(newRootItem, dynamic_cast<CTCP_Manager*>(PacketObjects[row].get()));
    }
    else {
        this->UpdateUDP_Tree(newRootItem, dynamic_cast<CUDP_Manager*>(PacketObjects[row].get()));
    }

    All_Tree_Item.push_back(newRootItem);

    SummaryTable[static_cast<int>(TYPE::ALL)]->scrollToBottom();
}

void MainWindow::UpdateTCP_Form() {
    int row = TableModel[static_cast<int>(TYPE::TCP)]->rowCount();

    UpdateSummaryTable(TYPE::TCP, row, TCP_Ptrs[row].get());

    QStandardItemModel* newRootItem = new QStandardItemModel(this);
    newRootItem->insertColumns(0, 1);
    newRootItem->setHeaderData(0, Qt::Horizontal, "Packet analysis contents");
    this->UpdateETH_Tree(newRootItem, dynamic_cast<CEthernetManager*>(TCP_Ptrs[row].get()));
    this->UpdateIP_Tree(newRootItem, dynamic_cast<CIP_Manager*>(TCP_Ptrs[row].get()));
    this->UpdateTCP_Tree(newRootItem, TCP_Ptrs[row].get());

    TCP_Tree_Item.push_back(newRootItem);

    SummaryTable[static_cast<int>(TYPE::TCP)]->scrollToBottom();
}

void MainWindow::UpdateUDP_Form() {
    int row = TableModel[static_cast<int>(TYPE::UDP)]->rowCount();

    UpdateSummaryTable(TYPE::UDP, row, UDP_Ptrs[row].get());

    QStandardItemModel* newRootItem = new QStandardItemModel(this);
    newRootItem->insertColumns(0, 1);
    newRootItem->setHeaderData(0, Qt::Horizontal, "Packet analysis contents");
    this->UpdateETH_Tree(newRootItem, dynamic_cast<CEthernetManager*>(UDP_Ptrs[row].get()));
    this->UpdateIP_Tree(newRootItem, dynamic_cast<CIP_Manager*>(UDP_Ptrs[row].get()));
    this->UpdateUDP_Tree(newRootItem, UDP_Ptrs[row].get());

    UDP_Tree_Item.push_back(newRootItem);

    SummaryTable[static_cast<int>(TYPE::UDP)]->scrollToBottom();
}

void MainWindow::UpdateHTTP_Form() {
    int row = TableModel[static_cast<int>(TYPE::HTTP)]->rowCount();

    UpdateSummaryTable(TYPE::HTTP, row, HTTP_Ptrs[row].get());

    QStandardItemModel* newRootItem = new QStandardItemModel(this);
    newRootItem->insertColumns(0, 1);
    newRootItem->setHeaderData(0, Qt::Horizontal, "Packet analysis contents");
    this->UpdateETH_Tree(newRootItem, dynamic_cast<CEthernetManager*>(HTTP_Ptrs[row].get()));
    this->UpdateIP_Tree(newRootItem, dynamic_cast<CIP_Manager*>(HTTP_Ptrs[row].get()));
    this->UpdateTCP_Tree(newRootItem, dynamic_cast<CTCP_Manager*>(HTTP_Ptrs[row].get()));
    this->UpdateHTTP_Tree(newRootItem, HTTP_Ptrs[row].get());

    HTTP_Tree_Item.push_back(newRootItem);

    SummaryTable[static_cast<int>(TYPE::HTTP)]->scrollToBottom();
}

void MainWindow::UpdateFTP_Form() {
    int row = TableModel[static_cast<int>(TYPE::FTP)]->rowCount();

    UpdateSummaryTable(TYPE::FTP, row, FTP_Ptrs[row].get());

    QStandardItemModel* newRootItem = new QStandardItemModel(this);
    newRootItem->insertColumns(0, 1);
    newRootItem->setHeaderData(0, Qt::Horizontal, "Packet analysis contents");
    this->UpdateETH_Tree(newRootItem, dynamic_cast<CEthernetManager*>(FTP_Ptrs[row].get()));
    this->UpdateIP_Tree(newRootItem, dynamic_cast<CIP_Manager*>(FTP_Ptrs[row].get()));
    this->UpdateTCP_Tree(newRootItem, dynamic_cast<CTCP_Manager*>(FTP_Ptrs[row].get()));
    this->UpdateFTP_Tree(newRootItem, FTP_Ptrs[row].get());

    FTP_Tree_Item.push_back(newRootItem);

    SummaryTable[static_cast<int>(TYPE::FTP)]->scrollToBottom();
}

void MainWindow::UpdateTELNET_Form() {
    int row = TableModel[static_cast<int>(TYPE::TELNET)]->rowCount();

    UpdateSummaryTable(TYPE::TELNET, row, TELNET_Ptrs[row].get());

    QStandardItemModel* newRootItem = new QStandardItemModel(this);
    newRootItem->insertColumns(0, 1);
    newRootItem->setHeaderData(0, Qt::Horizontal, "Packet analysis contents");
    this->UpdateETH_Tree(newRootItem, dynamic_cast<CEthernetManager*>(TELNET_Ptrs[row].get()));
    this->UpdateIP_Tree(newRootItem, dynamic_cast<CIP_Manager*>(TELNET_Ptrs[row].get()));
    this->UpdateTCP_Tree(newRootItem, dynamic_cast<CTCP_Manager*>(TELNET_Ptrs[row].get()));
    this->UpdateTELNET_Tree(newRootItem, TELNET_Ptrs[row].get());

    TELNET_Tree_Item.push_back(newRootItem);

    SummaryTable[static_cast<int>(TYPE::TELNET)]->scrollToBottom();
}

void MainWindow::UpdateDNS_Form() {
    int row = TableModel[static_cast<int>(TYPE::DNS)]->rowCount();

    UpdateSummaryTable(TYPE::DNS, row, DNS_Ptrs[row].get());

    QStandardItemModel* newRootItem = new QStandardItemModel(this);
    newRootItem->insertColumns(0, 1);
    newRootItem->setHeaderData(0, Qt::Horizontal, "Packet analysis contents");
    this->UpdateETH_Tree(newRootItem, dynamic_cast<CEthernetManager*>(DNS_Ptrs[row].get()));
    this->UpdateIP_Tree(newRootItem, dynamic_cast<CIP_Manager*>(DNS_Ptrs[row].get()));
    this->UpdateUDP_Tree(newRootItem, dynamic_cast<CUDP_Manager*>(DNS_Ptrs[row].get()));
    this->UpdateDNS_Tree(newRootItem, DNS_Ptrs[row].get());

    DNS_Tree_Item.push_back(newRootItem);

    SummaryTable[static_cast<int>(TYPE::DNS)]->scrollToBottom();
}

void MainWindow::UpdateETH_Tree(QStandardItemModel* RootItem, CEthernetManager* pETH) {
    QStandardItem* Root = new QStandardItem("Ethernet Section");

    std::string SrcMAC("Source MAC Address");      SrcMAC.resize(FiledWidth, ' ');     SrcMAC += " : " + pETH->GetSrcMAC();
    std::string DstMAC("Destination MAC Address");      DstMAC.resize(FiledWidth, ' ');     DstMAC += " : " + pETH->GetDstMAC();
    std::string EthType("Ethernet Type");          EthType.resize(FiledWidth, ' ');    EthType += " : " + pETH->GetEtherType();
    std::string TotalSize("Total Packet Size"); TotalSize.resize(FiledWidth, ' ');  TotalSize += " : ";

    QStandardItem* Item[] = {
        new QStandardItem(SrcMAC.c_str()),
        new QStandardItem(DstMAC.c_str()),
        new QStandardItem(EthType.c_str()),
        new QStandardItem(TotalSize.c_str() + QString::number(pETH->GetPacketLen()))
    };

    for(int idx = 0; idx < sizeof(Item)/sizeof(QStandardItem*); idx++)
        Root->appendRow(Item[idx]);

    RootItem->appendRow(Root);
}

void MainWindow::UpdateIP_Tree(QStandardItemModel* RootItem, CIP_Manager* pIP) {
    QStandardItem* Root = new QStandardItem("IP Section");

    std::string IpVer("IP Version");                IpVer.resize(FiledWidth, ' ');      IpVer += " : " + pIP->Get_IP_Version();
    std::string IphLen("IP Header Length");         IphLen.resize(FiledWidth, ' ');     IphLen += " : ";
    std::string IpTOV("IP Type Of Service");        IpTOV.resize(FiledWidth, ' ');      IpTOV += " : " + pIP->Get_IP_Type_Of_Service();
    std::string IpTotalLen("IP Total Length");      IpTotalLen.resize(FiledWidth, ' '); IpTotalLen += " : ";
    std::string IpFragID("IP Fragment ID Num");     IpFragID.resize(FiledWidth, ' ');   IpFragID += " : ";
    std::string IpFragFlag("IP Fragmentation Flag");IpFragFlag.resize(FiledWidth, ' '); IpFragFlag += " : " + pIP->Get_IP_Fragmentation_Flags();
    std::string IpFragOff("IP Fragment Offset");    IpFragOff.resize(FiledWidth, ' ');  IpFragOff += " : ";
    std::string IpTTL("IP Time To Live");           IpTTL.resize(FiledWidth, ' ');      IpTTL += " : ";
    std::string IpOptLen("IP Option Length");       IpOptLen.resize(FiledWidth, ' ');   IpOptLen += " : ";
    std::string ProtocolID("Protocol Identifier");  ProtocolID.resize(FiledWidth, ' '); ProtocolID += " : " + pIP->Get_IP_Protocol_Identifier();
    std::string IpChecksum("IP Checksum");          IpChecksum.resize(FiledWidth, ' '); IpChecksum += " : ";
    std::string SrcIP("IP Source Address");         SrcIP.resize(FiledWidth, ' ');      SrcIP += " : " + pIP->Get_Src_IP_Address();
    std::string DstIP("IP Destination Address");    DstIP.resize(FiledWidth, ' ');      DstIP += " : " + pIP->Get_Dst_IP_Address();

    QStandardItem* Item[] = {
        new QStandardItem(IpVer.c_str()),
        new QStandardItem(IphLen.c_str() + QString::number(pIP->Get_IP_Header_Length())),
        new QStandardItem(IpTOV.c_str()),
        new QStandardItem(IpTotalLen.c_str() + QString::number(pIP->Get_IP_Total_Packet_Length())),
        new QStandardItem(IpFragID.c_str() + QString::number(pIP->Get_IP_Fragment_Identifier())),
        new QStandardItem(IpFragFlag.c_str()),
        new QStandardItem(IpFragOff.c_str() + QString::number(pIP->Get_IP_Fragmentation_Offset())),
        new QStandardItem(IpTTL.c_str() + QString::number(pIP->Get_IP_Time_To_Live())),
        new QStandardItem(IpOptLen.c_str() + QString::number(pIP->Get_IP_Option_Length())),
        new QStandardItem(ProtocolID.c_str()),
        new QStandardItem(IpChecksum.c_str() + QString::number(pIP->Get_IP_Header_Checksum())),
        new QStandardItem(SrcIP.c_str()),
        new QStandardItem(DstIP.c_str())
    };

    for(int idx = 0; idx < sizeof(Item)/sizeof(QStandardItem*); idx++)
        Root->appendRow(Item[idx]);

    RootItem->appendRow(Root);
}

void MainWindow::UpdateTCP_Tree(QStandardItemModel* RootItem, CTCP_Manager* pTCP) {
    QStandardItem* Root = new QStandardItem("TCP Section");

    std::string SeqNum("TCP SEQ Number");           SeqNum.resize(FiledWidth, ' ');     SeqNum += " : ";
    std::string AckNum("TCP ACK Number");           AckNum.resize(FiledWidth, ' ');     AckNum += " : ";
    std::string HeaderLen("TCP Header Length");     HeaderLen.resize(FiledWidth, ' ');  HeaderLen += " : ";
    std::string CtrlFlags("TCP Control Flags");     CtrlFlags.resize(FiledWidth, ' ');  CtrlFlags += " : " + pTCP->Get_TCP_Control_Flags();
    std::string WinSize("TCP Window Size");         WinSize.resize(FiledWidth, ' ');    WinSize += " : ";
    std::string CheckSum("TCP Checksum");           CheckSum.resize(FiledWidth, ' ');   CheckSum += " : ";
    std::string UrgPoint("TCP Urgent Point");       UrgPoint.resize(FiledWidth, ' ');   UrgPoint += " : ";
    std::string OptLen("TCP Option Length");        OptLen.resize(FiledWidth, ' ');     OptLen += " : ";
    std::string SrcPort("TCP Source Port Number");  SrcPort.resize(FiledWidth, ' ');    SrcPort += " : ";
    std::string DstPort("TCP Destination Number");  DstPort.resize(FiledWidth, ' ');    DstPort += " : ";

    QStandardItem* Item[] = {
        new QStandardItem(SeqNum.c_str() + QString::number(pTCP->Get_TCP_Sequence_Number())),
        new QStandardItem(AckNum.c_str() + QString::number(pTCP->Get_TCP_Acknowledgement_Number())),
        new QStandardItem(HeaderLen.c_str() + QString::number(pTCP->Get_TCP_Header_Length())),
        new QStandardItem((CtrlFlags.c_str() + pTCP->Get_TCP_Control_Flags()).c_str()),
        new QStandardItem(WinSize.c_str() + QString::number(pTCP->Get_TCP_Window_Size())),
        new QStandardItem(CheckSum.c_str() + QString::number(pTCP->Get_TCP_Checksum())),
        new QStandardItem(UrgPoint.c_str() + QString::number(pTCP->Get_TCP_Urgent_Point())),
        new QStandardItem(OptLen.c_str() + QString::number(pTCP->Get_TCP_Option_Length())),
        new QStandardItem(SrcPort.c_str() + QString::number(pTCP->Get_Src_Port())),
        new QStandardItem(DstPort.c_str() + QString::number(pTCP->Get_Dst_Port()))
    };

    for(int idx = 0; idx < sizeof(Item)/sizeof(QStandardItem*); idx++)
        Root->appendRow(Item[idx]);

    RootItem->appendRow(Root);
}

void MainWindow::UpdateUDP_Tree(QStandardItemModel* RootItem, CUDP_Manager* pUDP) {
    QStandardItem* Root = new QStandardItem("UDP Section");

    std::string CheckSum("UDP Checksum");               CheckSum.resize(FiledWidth, ' ');   CheckSum += " : ";
    std::string UdpLen("UDP Length");                   UdpLen.resize(FiledWidth, ' ');     UdpLen += " : ";
    std::string SrcPort("UDP Source Port Number");      SrcPort.resize(FiledWidth, ' ');    SrcPort += " : ";
    std::string DstPort("UDP Destination Port Number"); DstPort.resize(FiledWidth, ' ');    DstPort += " : ";

    QStandardItem* Item[] = {
        new QStandardItem(CheckSum.c_str() + QString::number(pUDP->Get_UDP_Checksum())),
        new QStandardItem(UdpLen.c_str() + QString::number(pUDP->Get_UDP_Payload_Length())),
        new QStandardItem(SrcPort.c_str() + QString::number(pUDP->Get_Src_Port())),
        new QStandardItem(DstPort.c_str() + QString::number(pUDP->Get_Dst_Port()))
    };

    for(int idx = 0; idx < sizeof(Item)/sizeof(QStandardItem*); idx++)
        Root->appendRow(Item[idx]);

    RootItem->appendRow(Root);
}

void MainWindow::UpdateHTTP_Tree(QStandardItemModel* RootItem, CHTTP_Manager* pHTTP) {
    QStandardItem* Root = new QStandardItem("HTTP Section");

    if(pHTTP->ID == HTTP_Identifier::Request_Header) {
        QStandardItem* RequestRoot = new QStandardItem("[ HTTP Request ]");
        QStandardItem* RequestFirst = new QStandardItem(pHTTP->HTTP_First_Line.c_str());

        Root->appendRow(RequestRoot);
        RequestRoot->appendRow(RequestFirst);
        for(int idx = 0; idx < pHTTP->HTTP_Header.size(); idx++) {
            QStandardItem* newItem = new QStandardItem(pHTTP->HTTP_Header[idx].c_str());
            RequestRoot->appendRow(newItem);
        }
    }
    else if(pHTTP->ID == HTTP_Identifier::Response_Header) {
        QStandardItem* ResponsetRoot = new QStandardItem("[ HTTP Response ]");
        QStandardItem* ResponseFirst = new QStandardItem(pHTTP->HTTP_First_Line.c_str());

        Root->appendRow(ResponsetRoot);
        ResponsetRoot->appendRow(ResponseFirst);
        for(int idx = 0; idx < pHTTP->HTTP_Header.size(); idx++) {
            QStandardItem* newItem = new QStandardItem(pHTTP->HTTP_Header[idx].c_str());
            ResponsetRoot->appendRow(newItem);
        }

        if(pHTTP->Data_Length.size() != 0) {
            QStandardItem* Chunk = new QStandardItem("[ Cunk Data : " + QString::number(pHTTP->Data_Length.size()) + " EA ]");
            Root->appendRow(Chunk);
            for(int idx = 0; idx < pHTTP->HTTP_Header.size(); idx++) {
                QStandardItem* newItem = new QStandardItem(QString::number(pHTTP->Data_Length[idx]));
                Chunk->appendRow(newItem);
            }
        }
    }
    else if(pHTTP->ID == HTTP_Identifier::Data) {
        QStandardItem* DataRoot = new QStandardItem("[ HTTP Data ]");
        Root->appendRow(DataRoot);
    }

    if(Root->rowCount() == 0)
        delete Root;
    else
        RootItem->appendRow(Root);
}

void MainWindow::UpdateFTP_Tree(QStandardItemModel* RootItem, CFTP_Manager* pFTP) {
    if(pFTP->Get_TCP_Payload_Length() == 0)
        return;

    QStandardItem* FTP_Root = new QStandardItem("FTP Section");
    if(pFTP->bFTP_Operating_Mode) {
        QStandardItem* FTP_Transport = new QStandardItem("File Transport Mode");
        if(pFTP->bDirectories) {
            std::stringstream ss(pFTP->FTP_Message);
            std::string token;

            QStandardItem* FTP_DirRoot = new QStandardItem("Directory List");
            while(getline(ss, token, '\n')) {
                size_t pos = token.find('\r', 0);
                token[pos] = '\0';

                QStandardItem* FTP_Dir = new QStandardItem(token.c_str());
                FTP_DirRoot->appendRow(FTP_Dir);
            }
            FTP_Transport->appendRow(FTP_DirRoot);
        }
        else {

        }
        FTP_Root->appendRow(FTP_Transport);
    }
    else {
        if(pFTP->bFTP_Connection_Mode) {
            std::string Ori("Original Message");    Ori.resize(FiledWidth - 2, ' ');    Ori += " : " + pFTP->FTP_Message;
            std::string Mean("Mean Of Reply Code"); Mean.resize(FiledWidth - 2, ' ');   Mean += " : " + pFTP->GetReplyCodeDiscription();

            QStandardItem* FTP_Response = new QStandardItem("Server Response");
            QStandardItem* FTP_Original = new QStandardItem(Ori.c_str());
            QStandardItem* FTP_Mean = new QStandardItem(Mean.c_str());

            FTP_Response->appendRow(FTP_Original);
            FTP_Response->appendRow(FTP_Mean);
            FTP_Root->appendRow(FTP_Response);
        }
        else {
            std::string Ori("Original Message");    Ori.resize(FiledWidth - 2, ' ');    Ori += " : " + pFTP->FTP_Message;
            std::string Mean("Mean Of Command"); Mean.resize(FiledWidth - 2, ' ');   Mean += " : " + pFTP->GetCommandDiscription();

            QStandardItem* FTP_Request = new QStandardItem("Client Request");
            QStandardItem* FTP_Original = new QStandardItem(Ori.c_str());
            QStandardItem* FTP_Mean = new QStandardItem(Mean.c_str());

            FTP_Request->appendRow(FTP_Original);
            FTP_Request->appendRow(FTP_Mean);
            FTP_Root->appendRow(FTP_Request);
        }
    }
    RootItem->appendRow(FTP_Root);
}

void MainWindow::UpdateDNS_Tree(QStandardItemModel* RootItem, CDNS_Manager* pDNS) {
    QStandardItem* Root = new QStandardItem("DNS Section");

    /* ------------------------------- Header Description ------------------------------------------ */
    QStandardItem* HeaderRoot = new QStandardItem("Header Section");

    std::string TransID("DNS Transaction ID");          TransID.resize(FiledWidth - 2, ' ');    TransID += " : ";
    std::string QueryCnt("DNS Question Count");         QueryCnt.resize(FiledWidth - 2, ' ');   QueryCnt += " : ";
    std::string AnsCnt("DNS Answer Count");             AnsCnt.resize(FiledWidth - 2, ' ');     AnsCnt += " : ";
    std::string ServCnt("DNS Name Server Count");       ServCnt.resize(FiledWidth - 2, ' ');    ServCnt += " : ";
    std::string RecCnt("DNS Information Record Count"); RecCnt.resize(FiledWidth - 2, ' ');     RecCnt += " : ";
    std::string QueryOrRes("DNS Query Or Response");    QueryOrRes.resize(FiledWidth - 2, ' '); QueryOrRes += " : " + pDNS->Get_DNS_Query_Or_Response();
    std::string OpCode("DNS Operation Code");           OpCode.resize(FiledWidth - 2, ' ');     OpCode += " : " + pDNS->Get_DNS_Operation_Code();
    std::string AutAns("DNS Author Answer");            AutAns.resize(FiledWidth - 2, ' ');     AutAns += " : " + pDNS->Get_DNS_Authoritative_Answer();
    std::string Trun("DNS Truncated");                  Trun.resize(FiledWidth - 2, ' ');       Trun += " : " + pDNS->Get_DNS_Truncated();
    std::string RecurDes("DNS Recursion Desired");      RecurDes.resize(FiledWidth - 2, ' ');   RecurDes += " : " + pDNS->Get_DNS_Recursion_Desired();
    std::string RecurAvail("DNS Recursion Available");  RecurAvail.resize(FiledWidth - 2, ' '); RecurAvail += " : " + pDNS->Get_DNS_Recursion_Available();
    std::string ResCode("DNS Response Code");           ResCode.resize(FiledWidth - 2, ' ');    ResCode += " : " + pDNS->Get_DNS_Response_Code();

    QStandardItem* HeaderItem[] = {
        new QStandardItem(TransID.c_str() + QString::number(pDNS->Get_DNS_Transaction_ID())),
        new QStandardItem(QueryCnt.c_str() + QString::number(pDNS->Get_DNS_Question_Count())),
        new QStandardItem(AnsCnt.c_str() + QString::number(pDNS->Get_DNS_Answer_Count())),
        new QStandardItem(ServCnt.c_str() + QString::number(pDNS->Get_DNS_Name_Server_Count())),
        new QStandardItem(RecCnt.c_str() + QString::number(pDNS->Get_DNS_Additional_Information_Record_Count())),
        new QStandardItem(QueryOrRes.c_str()),
        new QStandardItem(OpCode.c_str()),
        new QStandardItem(AutAns.c_str()),
        new QStandardItem(Trun.c_str()),
        new QStandardItem(RecurDes.c_str()),
        new QStandardItem(RecurAvail.c_str()),
        new QStandardItem(ResCode.c_str())
    };
    for(int idx = 0; idx < sizeof(HeaderItem)/sizeof(QStandardItem*); idx++)
        HeaderRoot->appendRow(HeaderItem[idx]);

    /* -------------------------------- Query Description ----------------------------------------- */
    QStandardItem* QueryRoot = new QStandardItem("Query Section");
    for(int idx = 0; idx < pDNS->Query_Msg.size(); idx++) {
        QStandardItem* QuerySpacer = new QStandardItem("The " + QString::number(idx + 1) + " of " + QString::number(pDNS->Query_Msg.size()) + " Query");

        std::string Name("Name");       Name.resize(FiledWidth - 4, ' ');   Name += " : " + pDNS->Query_Msg[idx].Name;
        std::string Type("Type");       Type.resize(FiledWidth - 4, ' ');   Type += " : " + pDNS->Query_Msg[idx].Type;
        std::string Class("Class");     Class.resize(FiledWidth - 4, ' ');  Class += " : " + pDNS->Query_Msg[idx].Class;

        QStandardItem* QueryName = new QStandardItem(Name.c_str());
        QStandardItem* QueryType = new QStandardItem(Type.c_str());
        QStandardItem* QueryClass = new QStandardItem(Class.c_str());

        QueryRoot->appendRow(QuerySpacer);
        QuerySpacer->appendRow(QueryName);
        QuerySpacer->appendRow(QueryType);
        QuerySpacer->appendRow(QueryClass);
    }

    /* -------------------------------- Answer Description ----------------------------------------- */
    QStandardItem* AnswerRoot = new QStandardItem("Answer Section");
    QStandardItem* ServerRoot = new QStandardItem("DNS Name Server Section");
    QStandardItem* AddInfoRoot = new QStandardItem("Add Info Record Section");
    for(int idx = 0; idx < pDNS->Answer_Msg.size(); idx++) {
        /* Answer Message */
        if(idx < pDNS->Get_DNS_Answer_Count()) {
            QStandardItem* AnswerSpacer = new QStandardItem("The " + QString::number(idx + 1) + " of " + QString::number(pDNS->Get_DNS_Answer_Count()) + " Answer");

            std::string Name("Name");                   Name.resize(FiledWidth - 4, ' ');   Name += " : " + pDNS->Answer_Msg[idx].Name;
            std::string Type("Type");                   Type.resize(FiledWidth - 4, ' ');   Type += " : " + pDNS->Answer_Msg[idx].Type;
            std::string Class("Class");                 Class.resize(FiledWidth - 4, ' ');  Class += " : " + pDNS->Answer_Msg[idx].Class;
            std::string TTL("Time To Live");            TTL.resize(FiledWidth - 4, ' ');    TTL += " : ";
            std::string RD_Len("Resource Data Length"); RD_Len.resize(FiledWidth - 4, ' '); RD_Len += " : ";

            QStandardItem* AnswerName = new QStandardItem(Name.c_str());
            QStandardItem* AnswerType = new QStandardItem(Type.c_str());
            QStandardItem* AnswerClass = new QStandardItem(Class.c_str());
            QStandardItem* AnswerTTL = new QStandardItem(TTL.c_str() + QString::number(pDNS->Answer_Msg[idx].Time_To_live));
            QStandardItem* AnswerRD_Len = new QStandardItem(RD_Len.c_str() + QString::number(pDNS->Answer_Msg[idx].Resource_Data_Length));

            AnswerRoot->appendRow(AnswerSpacer);
            AnswerSpacer->appendRow(AnswerName);
            AnswerSpacer->appendRow(AnswerType);
            AnswerSpacer->appendRow(AnswerClass);
            AnswerSpacer->appendRow(AnswerTTL);
            AnswerSpacer->appendRow(AnswerRD_Len);
            if(pDNS->Answer_Msg[idx].Resource_Data_Length != 0) {
                std::string rdData("Resource Data");    rdData.resize(FiledWidth - 4, ' '); rdData += " : " + pDNS->Answer_Msg[idx].Resource_Data;
                QStandardItem* AnswerRD = new QStandardItem(rdData.c_str());
                AnswerSpacer->appendRow(AnswerRD);
            }
        }
        /* Name Server Message */
        else if(idx < (pDNS->Get_DNS_Answer_Count() + pDNS->Get_DNS_Name_Server_Count())) {
            QStandardItem* ServerSpacer = new QStandardItem("The " + QString::number(idx - pDNS->Get_DNS_Answer_Count() + 1) + " of " + QString::number(pDNS->Get_DNS_Name_Server_Count()) + "Author Answer");

            std::string Name("Name");                   Name.resize(FiledWidth - 4, ' ');   Name += " : " + pDNS->Answer_Msg[idx].Name;
            std::string Type("Type");                   Type.resize(FiledWidth - 4, ' ');   Type += " : " + pDNS->Answer_Msg[idx].Type;
            std::string Class("Class");                 Class.resize(FiledWidth - 4, ' ');  Class += " : " + pDNS->Answer_Msg[idx].Class;
            std::string TTL("Time To Live");            TTL.resize(FiledWidth - 4, ' ');    TTL += " : ";
            std::string rdLen("Resource Data Length");  rdLen.resize(FiledWidth - 4, ' ');  rdLen += " : ";

            QStandardItem* ServerName = new QStandardItem(Name.c_str());
            QStandardItem* ServerType = new QStandardItem(Type.c_str());
            QStandardItem* ServerClass = new QStandardItem(Class.c_str());
            QStandardItem* ServerTTL = new QStandardItem(TTL.c_str() + QString::number(pDNS->Answer_Msg[idx].Time_To_live));
            QStandardItem* ServerRD_Len = new QStandardItem(rdLen.c_str() + QString::number(pDNS->Answer_Msg[idx].Resource_Data_Length));

            ServerRoot->appendRow(ServerSpacer);
            ServerSpacer->appendRow(ServerName);
            ServerSpacer->appendRow(ServerType);
            ServerSpacer->appendRow(ServerClass);
            ServerSpacer->appendRow(ServerTTL);
            ServerSpacer->appendRow(ServerRD_Len);

            if(pDNS->Name_Server_Msg.size() != 0) {
                std::string Primary("Primary Server Name"); Primary.resize(FiledWidth - 2, ' ');    Primary += " : " + pDNS->Name_Server_Msg[idx - pDNS->Get_DNS_Answer_Count()].Primary_Name;
                std::string MailBox("Authority MailBox");   MailBox.resize(FiledWidth - 2, ' ');    MailBox += " : " + pDNS->Name_Server_Msg[idx - pDNS->Get_DNS_Answer_Count()].Responsible_authority_Mailbox;
                std::string Serial("Serial Number");        Serial.resize(FiledWidth - 2, ' ');     Serial += " : ";
                std::string Refresh("Refresh Interval");    Refresh.resize(FiledWidth - 2, ' ');    Refresh += " : ";
                std::string Retry("Retry Interval");        Retry.resize(FiledWidth - 2, ' ');      Retry += " : ";
                std::string Expire("Expire Limit");         Expire.resize(FiledWidth - 2, ' ');     Expire += " : ";
                std::string MinTTL("Minimum Time To Live"); MinTTL.resize(FiledWidth - 2, ' ');     MinTTL += " : ";

                QStandardItem* ServerPrimary = new QStandardItem(Primary.c_str());
                QStandardItem* ServerMailBox = new QStandardItem(MailBox.c_str());
                QStandardItem* ServerSerial = new QStandardItem(Serial.c_str() + QString::number(pDNS->Name_Server_Msg[idx - pDNS->Get_DNS_Answer_Count()].Serial_Number));
                QStandardItem* ServerRefresh = new QStandardItem(Refresh.c_str() + QString::number(pDNS->Name_Server_Msg[idx - pDNS->Get_DNS_Answer_Count()].Refresh_Interval));
                QStandardItem* ServerRetry = new QStandardItem(Retry.c_str() + QString::number(pDNS->Name_Server_Msg[idx - pDNS->Get_DNS_Answer_Count()].Retry_Interval));
                QStandardItem* ServerExpire = new QStandardItem(Expire.c_str() + QString::number(pDNS->Name_Server_Msg[idx - pDNS->Get_DNS_Answer_Count()].Expire_Limit));
                QStandardItem* ServerMinTTL = new QStandardItem(MinTTL.c_str() + QString::number(pDNS->Name_Server_Msg[idx - pDNS->Get_DNS_Answer_Count()].Minimum_Time_To_Live));

                ServerSpacer->appendRow(ServerPrimary);
                ServerSpacer->appendRow(ServerMailBox);
                ServerSpacer->appendRow(ServerSerial);
                ServerSpacer->appendRow(ServerRefresh);
                ServerSpacer->appendRow(ServerRetry);
                ServerSpacer->appendRow(ServerExpire);
                ServerSpacer->appendRow(ServerMinTTL);
            }
        }
        /* Add Info Message */
        else if(idx < (pDNS->Get_DNS_Answer_Count() + pDNS->Get_DNS_Name_Server_Count() + pDNS->Get_DNS_Additional_Information_Record_Count())) {
            uint16_t RcodeEx = (pDNS->Answer_Msg[idx].Time_To_live & 0xFF000000) >> 24;
            uint16_t Version = (pDNS->Answer_Msg[idx].Time_To_live & 0x00FF0000) >> 16;
            uint16_t D0 = (pDNS->Answer_Msg[idx].Time_To_live & 0x000080000);
            uint16_t Z = (pDNS->Answer_Msg[idx].Time_To_live & 0x0000007F);

            QStandardItem* AddInfoSpacer = new QStandardItem("The " + QString::number(idx - pDNS->Get_DNS_Answer_Count() - pDNS->Get_DNS_Additional_Information_Record_Count() + 1) + " of " + QString::number(pDNS->Get_DNS_Additional_Information_Record_Count()) + "Additional Information");

            std::string Name("Name");                   Name.resize(FiledWidth - 4, ' ');       Name += " : " + pDNS->Answer_Msg[idx].Name;
            std::string Type("Type");                   Type.resize(FiledWidth - 4, ' ');       Type += " : " + pDNS->Answer_Msg[idx].Type;
            std::string PaySize("UDP Payload Size");    PaySize.resize(FiledWidth - 4, ' ');    PaySize += " : " + pDNS->Answer_Msg[idx].Class;
            std::string ExRCode("Extended RCODE");      ExRCode.resize(FiledWidth - 4, ' ');    ExRCode += " : ";
            std::string Ver("Version");                 Ver.resize(FiledWidth - 4, ' ');        Ver += " : ";
            std::string D0_Bit("D0 Bit");               D0_Bit.resize(FiledWidth - 4, ' ');     D0_Bit += " : ";
            std::string Z_Data("Z");                    Z_Data.resize(FiledWidth - 4, ' ');     Z_Data += " : ";
            std::string Length("Length Of All RDATA");  Length.resize(FiledWidth - 4, ' ');     Length += " : ";

            QStandardItem* AddInfoName = new QStandardItem(Name.c_str());
            QStandardItem* AddInfoType = new QStandardItem(Type.c_str());
            QStandardItem* AddInfoPaySize = new QStandardItem(PaySize.c_str());
            QStandardItem* AddInfoExRCode = new QStandardItem(ExRCode.c_str() + QString::number(RcodeEx));
            QStandardItem* AddInfoVer = new QStandardItem(Ver.c_str() + QString::number(Version));
            QStandardItem* AddInfoD0 = new QStandardItem(D0_Bit.c_str() + QString::number(D0));
            QStandardItem* AddInfoZ = new QStandardItem(Z_Data.c_str() + QString::number(Z));
            QStandardItem* AddInfoLen = new QStandardItem(Length.c_str() + QString::number(pDNS->Answer_Msg[idx].Resource_Data_Length));

            AddInfoRoot->appendRow(AddInfoSpacer);
            AddInfoSpacer->appendRow(AddInfoName);
            AddInfoSpacer->appendRow(AddInfoType);
            AddInfoSpacer->appendRow(AddInfoPaySize);
            AddInfoSpacer->appendRow(AddInfoExRCode);
            AddInfoSpacer->appendRow(AddInfoVer);
            AddInfoSpacer->appendRow(AddInfoD0);
            AddInfoSpacer->appendRow(AddInfoZ);
            AddInfoSpacer->appendRow(AddInfoLen);
        }
    }

    /* Add Items */
    Root->appendRow(HeaderRoot);
    if(QueryRoot->rowCount() == 0)
        delete QueryRoot;
    else
        Root->appendRow(QueryRoot);
    if(AnswerRoot->rowCount() == 0)
        delete AnswerRoot;
    else
        Root->appendRow(AnswerRoot);
    if(ServerRoot->rowCount() == 0)
        delete ServerRoot;
    else
        Root->appendRow(ServerRoot);
    if(AddInfoRoot->rowCount() == 0)
        delete AddInfoRoot;
    else
        Root->appendRow(AddInfoRoot);

    RootItem->appendRow(Root);
}

void MainWindow::UpdateTELNET_Tree(QStandardItemModel* RootItem, CTelnet_Manager* pTELNET) {
    if(pTELNET->bEmpty)
        return;

    QStandardItem* TelnetRoot = new QStandardItem("Telnet Section");
    if(pTELNET->bCtrlMode) {
        QStandardItem* CtrlRoot = new QStandardItem("[ Control Message " + QString::number(pTELNET->Opt.size()) + " EA ]");
        for(int idx = 0; idx < pTELNET->Opt.size(); idx++) {
            QStandardItem* CtrlCmdRoot = new QStandardItem("The " + QString::number(idx + 1) + " Of " + QString::number(pTELNET->Opt.size()) + " Command Message.");

            std::string Cmd("Command"); Cmd.resize(8, ' ');    Cmd += " : " + pTELNET->GetCmdName(pTELNET->Opt[idx].CmdCode);
            std::string Opt("Option");  Opt.resize(8, ' ');    Opt += " : " + pTELNET->GetOptName(pTELNET->Opt[idx].OptCode);

            QStandardItem* CtrlCmd = new QStandardItem(Cmd.c_str());
            QStandardItem* CtrlOpt = new QStandardItem(Opt.c_str());

            CtrlCmdRoot->appendRow(CtrlCmd);
            CtrlCmdRoot->appendRow(CtrlOpt);
            if(TelnetCmd(pTELNET->Opt[idx].CmdCode) == TelnetCmd::SubNegotiate) {
                QStandardItem* CtrlSubOpt = new QStandardItem(pTELNET->Opt[idx].Value.c_str());
                CtrlCmdRoot->appendRow(CtrlSubOpt);
            }
            CtrlRoot->appendRow(CtrlCmdRoot);
        }
        TelnetRoot->appendRow(CtrlRoot);
    }
    else {
        char* buf = new char[pTELNET->Get_TCP_Payload_Length() + 1];
        memset(buf, 0, pTELNET->Get_TCP_Payload_Length() + 1);
        memcpy(buf, pTELNET->Get_TCP_Payload_Entry(), pTELNET->Get_TCP_Payload_Length());

        QStandardItem* DataRoot = new QStandardItem("[ Data... ]");
        TelnetRoot->appendRow(DataRoot);

        delete buf;
    }

    RootItem->appendRow(TelnetRoot);
}

void MainWindow::on_All_Table_clicked(const QModelIndex &index)
{
    const int row = index.row();

    DetailTree->setModel(All_Tree_Item[row]);
    DetailTree->expandAll();

    std::string OutputRaw;
    OutputRaw += CEthernetManager::GetRawData(PacketObjects[row]->GetEtherEntry(), PacketObjects[row]->GetPacketLen());

    ui->RawText->setPlainText(OutputRaw.c_str());
}

void MainWindow::on_TCP_Table_clicked(const QModelIndex &index)
{
    const int row = index.row();

    DetailTree->setModel(TCP_Tree_Item[row]);
    DetailTree->expandAll();

    std::string OutputRaw;
    OutputRaw += "[ Ethernet Section ]\n";
    OutputRaw += CEthernetManager::GetRawData(TCP_Ptrs[row]->GetEtherEntry(), TCP_Ptrs[row]->GetEthHeaderLen());

    OutputRaw += "\n[ IP Section ]\n";
    OutputRaw += CEthernetManager::GetRawData(TCP_Ptrs[row]->Get_IP_Header_Entry(), TCP_Ptrs[row]->Get_IP_Header_Length());

    OutputRaw += "\n[ TCP Section ]\n";
    OutputRaw += CEthernetManager::GetRawData(TCP_Ptrs[row]->Get_TCP_Entry(), TCP_Ptrs[row]->Get_TCP_Header_Length());

    OutputRaw += "\n[ TCP Payload ]\n";
    OutputRaw += CEthernetManager::GetRawData(TCP_Ptrs[row]->Get_TCP_Payload_Entry(), TCP_Ptrs[row]->Get_TCP_Payload_Length());

    ui->RawText->setPlainText(OutputRaw.c_str());
}

void MainWindow::on_UDP_Table_clicked(const QModelIndex &index)
{
    const int row = index.row();

    DetailTree->setModel(UDP_Tree_Item[row]);
    DetailTree->expandAll();

    std::string OutputRaw;
    OutputRaw += "[ Ethernet Section ]\n";
    OutputRaw += CEthernetManager::GetRawData(UDP_Ptrs[row]->GetEtherEntry(), UDP_Ptrs[row]->GetEthHeaderLen());

    OutputRaw += "\n[ IP Section ]\n";
    OutputRaw += CEthernetManager::GetRawData(UDP_Ptrs[row]->Get_IP_Header_Entry(), UDP_Ptrs[row]->Get_IP_Header_Length());

    OutputRaw += "\n[ UDP Section ]\n";
    OutputRaw += CEthernetManager::GetRawData(UDP_Ptrs[row]->Get_UDP_Entry(), UDP_Ptrs[row]->Get_UDP_Header_Len());

    OutputRaw += "\n[ UDP Payload ]\n";
    OutputRaw += CEthernetManager::GetRawData(UDP_Ptrs[row]->Get_UDP_Payload_Entry(), UDP_Ptrs[row]->Get_UDP_Payload_Length());

    ui->RawText->setPlainText(OutputRaw.c_str());
}

void MainWindow::on_HTTP_Table_clicked(const QModelIndex &index)
{
    const int row = index.row();

    DetailTree->setModel(HTTP_Tree_Item[row]);
    DetailTree->expandAll();

    std::string OutputRaw;
    OutputRaw += "[ Ethernet Section ]\n";
    OutputRaw += CEthernetManager::GetRawData(HTTP_Ptrs[row]->GetEtherEntry(), HTTP_Ptrs[row]->GetEthHeaderLen());

    OutputRaw += "\n[ IP Section ]\n";
    OutputRaw += CEthernetManager::GetRawData(HTTP_Ptrs[row]->Get_IP_Header_Entry(), HTTP_Ptrs[row]->Get_IP_Header_Length());

    OutputRaw += "\n[ TCP Section ]\n";
    OutputRaw += CEthernetManager::GetRawData(HTTP_Ptrs[row]->Get_TCP_Entry(), HTTP_Ptrs[row]->Get_TCP_Header_Length());

    OutputRaw += "\n[ HTTP Section ]\n";
    if(HTTP_Ptrs[row]->ID == HTTP_Identifier::Empty) {
        OutputRaw += ">> Empty....\n";
        ui->MachiningText->clear();
    }
    else if(HTTP_Ptrs[row]->ID == HTTP_Identifier::Data) {
        OutputRaw += ">> Data Chunk....\n";
        OutputRaw += CEthernetManager::GetRawData(HTTP_Ptrs[row]->Get_HTTP_Entry(), HTTP_Ptrs[row]->Get_HTTP_Len());

        ui->MachiningText->setPlainText(HTTP_Ptrs[row]->Get_HTTP_Data().c_str());
    }
    else if(HTTP_Ptrs[row]->ID == HTTP_Identifier::Request_Header) {
        OutputRaw += ">> Client Request\n";
        OutputRaw += CEthernetManager::GetRawData(HTTP_Ptrs[row]->Get_HTTP_Entry(), HTTP_Ptrs[row]->Get_HTTP_Len());
        ui->MachiningText->clear();
    }
    else if(HTTP_Ptrs[row]->ID == HTTP_Identifier::Response_Header) {
        OutputRaw += ">> Server Response\n";
        OutputRaw += CEthernetManager::GetRawData(HTTP_Ptrs[row]->Get_HTTP_Entry(), HTTP_Ptrs[row]->GetOffsetCnt());

        if(HTTP_Ptrs[row]->GetOffsetCnt() < HTTP_Ptrs[row]->Get_HTTP_Len()) {
            OutputRaw += "\n>> Data Chunk....\n";
            OutputRaw += CEthernetManager::GetRawData(HTTP_Ptrs[row]->Get_HTTP_Entry() + HTTP_Ptrs[row]->GetOffsetCnt(), HTTP_Ptrs[row]->Get_HTTP_Len() - HTTP_Ptrs[row]->GetOffsetCnt());
            ui->MachiningText->setPlainText(HTTP_Ptrs[row]->Get_HTTP_Data().c_str());
        }
        else
            ui->MachiningText->clear();
    }

    ui->RawText->setPlainText(OutputRaw.c_str());
}

void MainWindow::on_FTP_Table_clicked(const QModelIndex &index)
{
    const int row = index.row();

    DetailTree->setModel(FTP_Tree_Item[row]);
    DetailTree->expandAll();

    std::string OutputRaw;
    OutputRaw += "[ Ethernet Section ]\n";
    OutputRaw += CEthernetManager::GetRawData(FTP_Ptrs[row]->GetEtherEntry(), FTP_Ptrs[row]->GetEthHeaderLen());

    OutputRaw += "\n[ IP Section ]\n";
    OutputRaw += CEthernetManager::GetRawData(FTP_Ptrs[row]->Get_IP_Header_Entry(), FTP_Ptrs[row]->Get_IP_Header_Length());

    OutputRaw += "\n[ TCP Section ]\n";
    OutputRaw += CEthernetManager::GetRawData(FTP_Ptrs[row]->Get_TCP_Entry(), FTP_Ptrs[row]->Get_TCP_Header_Length());

    OutputRaw += "\n[ FTP Section ]\n";
    OutputRaw += CEthernetManager::GetRawData(FTP_Ptrs[row]->Get_FTP_Entry(), FTP_Ptrs[row]->Get_FTP_Len());

    ui->RawText->setPlainText(OutputRaw.c_str());

    if((FTP_Ptrs[row]->bFTP_Operating_Mode == true) && (FTP_Ptrs[row]->bDirectories == false)) {
        ui->MachiningText->setPlainText(FTP_Ptrs[row]->Get_TCP_Payload().c_str());
    }
    else
        ui->MachiningText->clear();
}

void MainWindow::on_TELNET_Table_clicked(const QModelIndex &index)
{
    const int row = index.row();

    DetailTree->setModel(TELNET_Tree_Item[row]);
    DetailTree->expandAll();


    std::string OutputRaw;
    OutputRaw += "[ Ethernet Section ]\n";
    OutputRaw += CEthernetManager::GetRawData(TELNET_Ptrs[row]->GetEtherEntry(), TELNET_Ptrs[row]->GetEthHeaderLen());

    OutputRaw += "\n[ IP Section ]\n";
    OutputRaw += CEthernetManager::GetRawData(TELNET_Ptrs[row]->Get_IP_Header_Entry(), TELNET_Ptrs[row]->Get_IP_Header_Length());

    OutputRaw += "\n[ TCP Section ]\n";
    OutputRaw += CEthernetManager::GetRawData(TELNET_Ptrs[row]->Get_TCP_Entry(), TELNET_Ptrs[row]->Get_TCP_Header_Length());

    OutputRaw += "\n[ TELNET Section ]\n";
    OutputRaw += CEthernetManager::GetRawData(TELNET_Ptrs[row]->Get_TELNET_Entry(), TELNET_Ptrs[row]->Get_TELNET_Len());

    ui->RawText->setPlainText(OutputRaw.c_str());
    if(TELNET_Ptrs[row]->bCtrlMode == false) {
        std::string buf = std::string((char*)TELNET_Ptrs[row]->Get_TELNET_Entry());
        ui->MachiningText->setPlainText(buf.c_str());
    }
    else
        ui->MachiningText->clear();
}

void MainWindow::on_DNS_Table_clicked(const QModelIndex &index)
{
    const int row = index.row();

    DetailTree->setModel(DNS_Tree_Item[row]);
    DetailTree->expandAll();

    std::string OutputRaw;
    OutputRaw += "[ Ethernet Section ]\n";
    OutputRaw += CEthernetManager::GetRawData(DNS_Ptrs[row]->GetEtherEntry(), DNS_Ptrs[row]->GetEthHeaderLen());

    OutputRaw += "\n[ IP Section ]\n";
    OutputRaw += CEthernetManager::GetRawData(DNS_Ptrs[row]->Get_IP_Header_Entry(), DNS_Ptrs[row]->Get_IP_Header_Length());

    OutputRaw += "\n[ UDP Section ]\n";
    OutputRaw += CEthernetManager::GetRawData(DNS_Ptrs[row]->Get_UDP_Entry(), DNS_Ptrs[row]->Get_UDP_Header_Len());

    OutputRaw += "\n[ DNS Section ]\n";
    OutputRaw += CEthernetManager::GetRawData(DNS_Ptrs[row]->Get_DNS_Entry(), DNS_Ptrs[row]->Get_DNS_Header_Len());

    OutputRaw += "\n[ DNS Payload ]\n";
    OutputRaw += CEthernetManager::GetRawData(DNS_Ptrs[row]->Get_DNS_Payload_Entry(), DNS_Ptrs[row]->Get_DNS_Payload_Lenght());

    ui->RawText->setPlainText(OutputRaw.c_str());
}

void MainWindow::on_PromiscButton_clicked()
{
    PromiscDialog* PromiscDlg = new PromiscDialog(this);

    if(PromiscDlg->exec()) {
        struct ifreq eth;

        NIC_Name = PromiscDlg->GetNIC_Name();
        strcpy(eth.ifr_name, NIC_Name.c_str());

        // Read.
        ioctl(this->RawSocketFd, SIOCGIFFLAGS, &eth);

        // Write.
        if(eth.ifr_flags & IFF_PROMISC) {
            eth.ifr_flags ^= IFF_PROMISC;
        }
        else {
            eth.ifr_flags |= IFF_PROMISC;
        }
        ioctl(this->RawSocketFd, SIOCSIFFLAGS, &eth);

    }
}

void MainWindow::Check_Promisc() {
    struct ifreq eth;

    StatusMessage.clear();
    StatusMessage += "[ Promisc ]";
    for(int idx= 0; idx < NIC_List.size(); idx++) {
        strcpy(eth.ifr_name, NIC_List[idx].c_str());

        // Read.
        ioctl(this->RawSocketFd, SIOCGIFFLAGS, &eth);
        if(eth.ifr_flags & IFF_PROMISC) {
            StatusMessage += "  " + NIC_List[idx] + "(ON)";
        }
        else {
            StatusMessage += "  " + NIC_List[idx] + "(OFF)";
        }
    }

    StatusMessage += " / " + EditorChecker;

    ui->statusBar->showMessage(StatusMessage.c_str());
}

void MainWindow::Read_NIC_List() {
    DIR* dp = nullptr;
    struct dirent* entry = nullptr;

    dp = opendir("/sys/class/net");

    while((entry = readdir(dp)) != nullptr) {
        if(entry->d_name[0] == '.')
            continue;

        NIC_List.push_back(std::string(entry->d_name));
    }

    closedir(dp);
}

void MainWindow::on_Begin_Button_clicked()
{
    ui->Stop_Button->setEnabled(true);
    ui->Begin_Button->setEnabled(false);
    bStart = true;

    ui->RawText->clear();
    ui->MachiningText->clear();
    DetailTree->setModel(nullptr);

    All_Tree_Item.clear();
    TCP_Tree_Item.clear();
    UDP_Tree_Item.clear();
    DNS_Tree_Item.clear();
    HTTP_Tree_Item.clear();
    TELNET_Tree_Item.clear();
    FTP_Tree_Item.clear();

    FTP_Ptrs.clear();
    TELNET_Ptrs.clear();
    HTTP_Ptrs.clear();
    DNS_Ptrs.clear();
    UDP_Ptrs.clear();
    TCP_Ptrs.clear();
    PacketObjects.clear();

    for(int idx = 0; idx < static_cast<int>(TYPE::COUNT); idx++) {
        this->TableModel[idx]->clear();

        this->TableModel[idx]->insertColumns(0, static_cast<int>(CAT::COUNT));
        this->TableModel[idx]->setHeaderData(static_cast<int>(CAT::SRC_IP), Qt::Horizontal, "Src IP");
        this->TableModel[idx]->setHeaderData(static_cast<int>(CAT::DST_IP), Qt::Horizontal, "Dst IP");
        this->TableModel[idx]->setHeaderData(static_cast<int>(CAT::SRC_PORT), Qt::Horizontal, "Src Port");
        this->TableModel[idx]->setHeaderData(static_cast<int>(CAT::DST_PORT), Qt::Horizontal, "Dst Port");
        this->TableModel[idx]->setHeaderData(static_cast<int>(CAT::SIZE), Qt::Horizontal, "Size");
        this->TableModel[idx]->setHeaderData(static_cast<int>(CAT::TRANSPORT), Qt::Horizontal, "Transport");
    }
    ResizeHandler();
}

void MainWindow::on_Stop_Button_clicked()
{
    ui->Begin_Button->setEnabled(true);
    ui->Stop_Button->setEnabled(false);
    bStart = false;
}

void MainWindow::on_Program_Information_Menu_clicked() {
    Information* Info = new Information(this);
    Info->show();
}

void MainWindow::on_MachiningText_textChanged()
{
    if(ui->MachiningText->toPlainText().length() == 0)
        EditorChecker = "[ Machining Data ] Empty";
    else
        EditorChecker = "[ Machining Data ] Exist";
}
