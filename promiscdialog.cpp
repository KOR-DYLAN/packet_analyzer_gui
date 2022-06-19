#include "promiscdialog.h"
#include "ui_promiscdialog.h"
#include <sys/types.h>
#include <dirent.h>

PromiscDialog::PromiscDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::PromiscDialog)
{
    ui->setupUi(this);

    ListModel = new QStandardItemModel(this);
    DIR* dp = nullptr;
    struct dirent* entry = nullptr;

    dp = opendir("/sys/class/net");


    while((entry = readdir(dp)) != nullptr) {
        if(entry->d_name[0] == '.')
            continue;

        QStandardItem* newDir = new QStandardItem(entry->d_name);
        ListModel->appendRow(newDir);
    }
    ui->PromiscListView->setModel(ListModel);

    if(ListModel->rowCount() == 0)
        ui->buttonBox->setEnabled(false);

    closedir(dp);
}

PromiscDialog::~PromiscDialog()
{
    delete ui;
}

void PromiscDialog::on_buttonBox_accepted()
{
    NIC_Name = ui->PromiscListView->currentIndex().data().toString().toStdString();
}

std::string PromiscDialog::GetNIC_Name() const {
    return NIC_Name;
}
