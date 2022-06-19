#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <vector>
#include <memory>

#include <sys/epoll.h>

#include <QMainWindow>
#include <QtGui>
#include <QTableView>
#include <QTreeView>
#include <QStandardItemModel>
#include <QStandardItem>
#include <QSystemTrayIcon>

#include "EthernetManager.h"
#include "IP_Manager.h"
#include "TCP_Manager.h"
#include "UDP_Manager.h"
#include "HTTP_Manager.h"
#include "Telnet_Manager.h"
#include "FTP_Manager.h"
#include "DNS_Manager.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:
    Ui::MainWindow *ui;
    QAbstractEventDispatcher* dispatcher;
protected:
    void resizeEvent(QResizeEvent* event) override;
private:
    void ResizeHandler();
    void CaptureLoop(uint8_t buf[], ssize_t recvLen);
    void Check_Promisc();
    void Read_NIC_List();
    std::vector<std::string> NIC_List;
    std::string StatusMessage;
    std::string EditorChecker;
private:
    enum class CAT : int { SRC_IP = 0, DST_IP, SRC_PORT, DST_PORT, SIZE, TRANSPORT, COUNT };
    enum class TYPE : int { ALL = 0, TCP, UDP, HTTP, FTP, TELNET, DNS, COUNT };
    QTableView* SummaryTable[static_cast<int>(TYPE::COUNT)];
    QTreeView* DetailTree;
    QStandardItemModel* TableModel[static_cast<int>(TYPE::COUNT)];

    std::vector<shared_ptr<CEthernetManager>> PacketObjects;
    std::vector<shared_ptr<CTCP_Manager>>     TCP_Ptrs;
    std::vector<shared_ptr<CUDP_Manager>>     UDP_Ptrs;
    std::vector<shared_ptr<CDNS_Manager>>     DNS_Ptrs;
    std::vector<shared_ptr<CHTTP_Manager>>    HTTP_Ptrs;
    std::vector<shared_ptr<CTelnet_Manager>>  TELNET_Ptrs;
    std::vector<shared_ptr<CFTP_Manager>>     FTP_Ptrs;

    std::vector<QStandardItemModel*> All_Tree_Item;
    std::vector<QStandardItemModel*> TCP_Tree_Item;
    std::vector<QStandardItemModel*> UDP_Tree_Item;
    std::vector<QStandardItemModel*> DNS_Tree_Item;
    std::vector<QStandardItemModel*> HTTP_Tree_Item;
    std::vector<QStandardItemModel*> TELNET_Tree_Item;
    std::vector<QStandardItemModel*> FTP_Tree_Item;

    bool bStart;
    std::string NIC_Name;
    int RawSocketFd;
    int epollFd;
    struct epoll_event epollEvent;
    struct epoll_event EventList;

    bool IsProtocol(TYPE ID, int port);
    void UpdateALL_Form();
    void UpdateTCP_Form();
    void UpdateUDP_Form();
    void UpdateHTTP_Form();
    void UpdateFTP_Form();
    void UpdateTELNET_Form();
    void UpdateDNS_Form();

    void UpdateSummaryTable(TYPE ID, int index, CEthernetManager* src);

    void UpdateETH_Tree(QStandardItemModel* RootItem, CEthernetManager* pETH);
    void UpdateIP_Tree(QStandardItemModel* RootItem, CIP_Manager* pIP);
    void UpdateTCP_Tree(QStandardItemModel* RootItem, CTCP_Manager* pTCP);
    void UpdateUDP_Tree(QStandardItemModel* RootItem, CUDP_Manager* pUDP);
    void UpdateHTTP_Tree(QStandardItemModel* RootItem, CHTTP_Manager* pHTTP);
    void UpdateFTP_Tree(QStandardItemModel* RootItem, CFTP_Manager* pFTP);
    void UpdateDNS_Tree(QStandardItemModel* RootItem, CDNS_Manager* pDNS);
    void UpdateTELNET_Tree(QStandardItemModel* RootItem, CTelnet_Manager* pTELNET);

private slots:
    void aboutToBlock();
    void on_tabWidget_currentChanged(int index);
    void on_All_Table_clicked(const QModelIndex &index);
    void on_TCP_Table_clicked(const QModelIndex &index);
    void on_UDP_Table_clicked(const QModelIndex &index);
    void on_HTTP_Table_clicked(const QModelIndex &index);
    void on_FTP_Table_clicked(const QModelIndex &index);
    void on_TELNET_Table_clicked(const QModelIndex &index);
    void on_DNS_Table_clicked(const QModelIndex &index);
    void on_PromiscButton_clicked();
    void on_Begin_Button_clicked();
    void on_Stop_Button_clicked();
    void on_Program_Information_Menu_clicked();
    void on_MachiningText_textChanged();
};

#endif // MAINWINDOW_H
