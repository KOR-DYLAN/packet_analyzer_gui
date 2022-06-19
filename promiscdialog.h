#ifndef PROMISCDIALOG_H
#define PROMISCDIALOG_H

#include <QDialog>
#include <QtGui>
#include <QStandardItemModel>
#include <QStandardItem>

namespace Ui {
class PromiscDialog;
}

class PromiscDialog : public QDialog
{
    Q_OBJECT

public:
    explicit PromiscDialog(QWidget *parent = nullptr);
    ~PromiscDialog();
    std::string GetNIC_Name() const;
private slots:
    void on_buttonBox_accepted();

private:
    Ui::PromiscDialog *ui;
    QStandardItemModel* ListModel;
    std::string NIC_Name;
};

#endif // PROMISCDIALOG_H
