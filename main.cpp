#include "BamSysInspector.h"
#include "SeDebugPrivilege.hh"

int main() {
    if (!EnableDebugPrivilege()) {
        std::wcerr << L"[!!] Could not enable SE_DEBUG_NAME privilege. Exiting." << std::endl;
        Sleep(2000);
        return 1;
    }

    std::wcout << L"Checking bam.sys presence...\n";

    if (FindBamSysThread()) {
        DisplaySystemBootTime();
    }

    std::wcout << L"\n";
    system("pause");
    return 0;
}
