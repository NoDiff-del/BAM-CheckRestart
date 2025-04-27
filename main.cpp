#include "BamSysInspector.h"

int main() {

    std::wcout << L"Checking bam.sys presence...\n";

    if (FindBamSysThread()) {
        DisplaySystemBootTime();
    }

    std::wcout << L"\n";
    system("pause");
    return 0;
}