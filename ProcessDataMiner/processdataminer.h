#ifndef PROCESSDATAMINER_H
#define PROCESSDATAMINER_H

// check if header Files have already being included before
#include <string>
#include <windows.h>
#include <tlHelp32.h>
#include <iostream>


using namespace std;

class ProcessDataMiner {
    public:
        ProcessDataMiner(void);                     // default constructor
        ProcessDataMiner(string proc_name);         // constructor initialize with process name
        BOOL findProcessId(void);                   // find the process with the text fragment <str_proc_name>
        BOOL findModuleInfo(DWORD);                 // find more information about the process found with findProcessID()
        void displayInfo(void);                     // for testing you can display information with this method
        void initPDM(string proc_name);             // if for what ever case the default constructor had been called the class must be initialized manually
    private:
        string str_proc_name;                       // text fragment the process being looked for contains
        DWORD proc_id;                              // process id provided by findProcessID()
        LPCVOID baseAddress;                        // base address of the found process provided by findModuleInfo(DWORD)
        SIZE_T size;                                // base address range size measured in bytes
        BOOL proc_found;                            // if a valid process has been found this variable will be TRUE
        LPBYTE buffer;
        SIZE_T numOfBytesRead;
};

// default constructor
ProcessDataMiner::ProcessDataMiner(void) {
    str_proc_name = "";
    proc_found = FALSE;
}

// constructor with process name
ProcessDataMiner::ProcessDataMiner(string proc_name) {
    str_proc_name = proc_name;
    proc_found = FALSE;

    if(findProcessId()) {
        if(!findModuleInfo(proc_id)) {
            cerr << "Something went wrong reading module info!" << endl;
        }
    }
    else {
        cerr << "No Process with the fragment " << str_proc_name << " in its name could be found!" << endl;
    }

    buffer = new BYTE[size];
    DWORD dwBlock, dwOffset;

    BYTE byte;

    string text="";

    if(Toolhelp32ReadProcessMemory(proc_id, baseAddress, buffer, size, &numOfBytesRead) == TRUE) {
        for(dwBlock = 0; dwBlock < size; dwBlock+=16) {
            for(dwOffset = 0; dwOffset < 16; dwOffset++) {
                byte =*(buffer+dwBlock+dwOffset);
                if(32 <= byte && byte < 127) {
                    text+=byte;
                }
            }
            if(text.find("Stockholm") != string::npos)
                cout << text << endl;
            text="";
        }
    }
}

/**
 * @brief ProcessDataMiner::initPDM
 * @param proc_name
 *
 * This method initialized the class in case the default constructor has been used.
 * If the default constructor has been called the element <str_proc_name> will be
 * empty thus leading other methods to fail because needed information is missing.
 */
void ProcessDataMiner::initPDM(string proc_name) {
    str_proc_name = proc_name;
    proc_found = FALSE;

    if(findProcessId()) {
        if(!findModuleInfo(proc_id)) {
            cerr << "Something went wrong reading module info!" << endl;
        }
    }
    else {
        cerr << "No Process with the fragment " << str_proc_name << " in its name could be found!" << endl;
    }
}

/**
 * @brief ProcessDataMiner::displayInfo
 *
 * This method briefly shows information about the initialized elements. It's useful
 * for debugging purposes.
 */
void ProcessDataMiner::displayInfo(void) {
    if(!proc_found) {
        cerr << "No Process could be found thus displyInfo(void) shows nothing!" << endl;
    }
    else {
        cout << "Process Name = " << str_proc_name << endl;
        cout << "Process ID   = " << proc_id << endl;
        cout << "Base address = " << baseAddress << endl;
        cout << "Base size    = " << size << endl;
    }
}


/**
 * @brief ProcessDataMiner::findProcessId
 * @return BOOL
 *
 * This method trys to find the process that contains the text fragment <str_proc_name>.
 * If it fails to find a process with that name the class initialization fails and you
 * cannot continue using the object.
 */
BOOL ProcessDataMiner::findProcessId(void) {
    HANDLE hProcessSnap;
    HANDLE hProcess;
    PROCESSENTRY32 pe32;
    DWORD dwPriorityClass;

    /* as we are trying to find the process again though we already found it once
     * -> proc_found == TRUE -> we reset the variable so the initialization would
     * crash unexpected
     */
    if(proc_found) {
        proc_found = FALSE;
    }

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hProcessSnap == INVALID_HANDLE_VALUE) {
        cerr << "CreateToolhelp32Snapshot (of processes)" << endl;
        return( FALSE );
    }

    // Set the size of the structure before using it.
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process, and exit if unsuccessful
    if(!Process32First(hProcessSnap, &pe32)) {
        cerr << "Process32First" << endl;
        CloseHandle(hProcessSnap);          // clean the snapshot object
        return(FALSE);
    }

    // Now walk the snapshot of processes to the the process <str_proc_name>
    do {
        // convert wchar_t into string
        wchar_t* txt = pe32.szExeFile;
        wstring ws(txt);
        string str(ws.begin(),ws.end());

        if (str.find(str_proc_name) != string::npos) {
            // Retrieve the priority class.
            dwPriorityClass = 0;
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);

            if(hProcess == NULL) {
                cerr << "printError: OpenProcess" << endl;
            }
            else {
                dwPriorityClass = GetPriorityClass(hProcess);
                if(!dwPriorityClass) {
                    cerr << "printError: GetPriorityClass" << endl;
                }
                CloseHandle(hProcess);
            }

            // forward process id to class element
            proc_id = pe32.th32ProcessID;
            CloseHandle(hProcessSnap);
            return(TRUE);
        }
    } while(Process32Next(hProcessSnap, &pe32));

    // nothing found. close handle and return false
    CloseHandle(hProcessSnap);
    return(FALSE);
}

/**
 * @brief ProcessDataMiner::findModuleInfo
 * @param dwPID
 * @return BOOL
 *
 * This method furthermore trys to find the base address and base address size of the
 * process being searched for. If it fails to do so the initialization of the object
 * fails again and you cannot continue using it.
 */
BOOL ProcessDataMiner::findModuleInfo(DWORD dwPID) {
    HANDLE hModuleSnap;
    MODULEENTRY32 me32;

    /* as we are trying to find the process information again though we already found some once
     * -> proc_found == TRUE -> we reset the variable so the initialization would crash unexpected
     */
    if(proc_found) {
        proc_found = FALSE;
    }

    // Take a snapshot of all modules in the specified process.
    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);

    // if the handle is invalid return false
    if(hModuleSnap == INVALID_HANDLE_VALUE) {
        cerr << "CreateToolhelp32Snapshot (of modules)" << endl;
        return(FALSE);
    }

    // Set the size of the structure before using it.
    me32.dwSize = sizeof(MODULEENTRY32);

    // Retrieve information about the first module, and exit if unsuccessful
    if(!Module32First(hModuleSnap, &me32)) {
        cerr << "Module32First" << endl;
        CloseHandle(hModuleSnap);           // clean the snapshot object
        return(FALSE);
    }

    // Now walk the module list of the process to find the module <str_proc_name>
    do {
        // convert wchar_t into string
        wchar_t* txt = me32.szExePath;
        wstring ws(txt);
        string exe_path(ws.begin(),ws.end());

        if (exe_path.find(str_proc_name) != string::npos) {
            baseAddress = me32.modBaseAddr;
            size = me32.modBaseSize;
            proc_found = TRUE;
            CloseHandle(hModuleSnap);
            return(TRUE);
        }
    } while(Module32Next(hModuleSnap, &me32));

    CloseHandle(hModuleSnap);
    return(FALSE);
}
#endif // PROCESSDATAMINER_H
