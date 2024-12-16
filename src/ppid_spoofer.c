#include <windows.h>
#include <stdio.h>
#include <tchar.h>

// Function to enable a privilege
BOOL EnablePrivilege(LPCTSTR privilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(
            NULL,       // lpSystemName
            privilege,  // lpName
            &luid       // lpLuid
            )) {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    HANDLE hToken;
    if (!OpenProcessToken(
            GetCurrentProcess(),        // ProcessHandle
            TOKEN_ADJUST_PRIVILEGES,    // DesiredAccess
            &hToken                     // TokenHandle
            )) {
        printf("OpenProcessToken error: %u\n", GetLastError());
        return FALSE;
    }

    if (!AdjustTokenPrivileges(
            hToken,                     // TokenHandle
            FALSE,                      // DisableAllPrivileges
            &tp,                        // NewState
            sizeof(TOKEN_PRIVILEGES),   // BufferLength
            NULL,                       // PreviousState
            NULL                        // ReturnLength
            )) {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: %s <Parent PID> <Executable Path> <Arguments>\n", argv[0]);
        return 1;
    }

    DWORD parentPid = atoi(argv[1]);
    char *exePath = argv[2];
    char *arguments = argv[3];

    // Enable the SeDebugPrivilege privilege
    if (!EnablePrivilege(SE_DEBUG_NAME)) {
        printf("Failed to enable SeDebugPrivilege\n");
        return FALSE;
    }

    // Get a handle to the parent process
    HANDLE hParentProcess = OpenProcess(
        PROCESS_CREATE_PROCESS,
        FALSE,
        parentPid
        );
    if (!hParentProcess) {
        printf("Failed to open parent process. Error: %lu\n", GetLastError());
        return 1;
    }

    STARTUPINFOEXA si = {0};
    PROCESS_INFORMATION pi = {0};
    SIZE_T attributeSize = 0;

    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    // Initialize attribute list
    InitializeProcThreadAttributeList(
        NULL,
        1,
        0,
        &attributeSize
        );
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attributeSize);
    if (!si.lpAttributeList) {
        printf("Failed to allocate memory for attribute list.\n");
        CloseHandle(hParentProcess);
        return 1;
    }

    if (!InitializeProcThreadAttributeList(
            si.lpAttributeList,
            1,
            0,
            &attributeSize
            )) {
        printf("Failed to initialize attribute list. Error: %lu\n", GetLastError());
        free(si.lpAttributeList);
        CloseHandle(hParentProcess);
        return 1;
    }

    // Set the parent process attribute
    if (!UpdateProcThreadAttribute(
            si.lpAttributeList,
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            &hParentProcess,
            sizeof(HANDLE),
            NULL,
            NULL
            )) {
        printf("Failed to update attribute list. Error: %lu\n", GetLastError());
        DeleteProcThreadAttributeList(si.lpAttributeList);
        free(si.lpAttributeList);
        CloseHandle(hParentProcess);
        return 1;
    }

    // Create the new process
    if (!CreateProcessA(
            exePath,
            arguments,
            NULL,
            NULL,
            FALSE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
            NULL,
            NULL,
            &si.StartupInfo,
            &pi
            )) {
        printf("Failed to create process. Error: %lu\n", GetLastError());
        DeleteProcThreadAttributeList(si.lpAttributeList);
        free(si.lpAttributeList);
        CloseHandle(hParentProcess);
        return 1;
    }

    printf("Process created successfully! PID: %lu\n", pi.dwProcessId);

    // Cleanup
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    DeleteProcThreadAttributeList(si.lpAttributeList);
    free(si.lpAttributeList);
    CloseHandle(hParentProcess);

    return 0;
}
