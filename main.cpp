#include "mainwindow.h"
#include <QApplication>
#include <unistd.h>
#include <string>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    if(getuid() != 0) {
        std::string path(argv[0]);
        std::string cmd("sudo ");
        cmd += path;
        system(cmd.c_str());
        exit(1);
    }

    QApplication app(argc, argv);
    MainWindow Window;

    Window.show();

    return app.exec();
}
