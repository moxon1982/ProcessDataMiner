#ifndef PROCESSDATAMINER_H
#define PROCESSDATAMINER_H

#include <string>
#include <windows.h>
#include <tlHelp32.h>
#include <iostream>

using namespace std;

class ProcessDataMiner {
    public:
        // Initialize the class
        ProcessDataMiner(void);                     // default constructor
        ProcessDataMiner(string& proc_name);        // constructor initialize with process name
        void initPDM(string& proc_name);            // if for what ever case the default constructor had been called the class must be initialized manually

        // functions to work with
        BOOL findProcessId(void);                   // find the process with the text fragment <str_procname>
        BOOL getHeapInfo(void);                     // another variant to find information about the process
        void displayInfo(void);                     // for testing you can display information with this method

        string chunk;                               // this might probably get an array and will be private -> will be replaced by a public method set to work with

        // probably obsolete funktions
        void mineForInfo(string& chunk);
        BOOL findModuleInfo(DWORD);                 // find more information about the process found with findProcessID()
    private:
        string str_procname;                        // text fragment the process being looked for contains
        DWORD dw_procid;                            // process id provided by findProcessID()
        void mineHeapForInfo(DWORD&, DWORD&);

        // these will probably become obsolete ->being replaced by the methods to read out the heap of the process
        LPCVOID lpcv_baseaddress;                   // base address of the found process provided by findModuleInfo(DWORD)
        SIZE_T sizet_modbasesize;                   // base address range size measured in bytes
        BOOL bool_procfound;                        // if a valid process has been found this variable will be TRUE
        LPBYTE lpb_buffer;                          // buffer to store read information into
        SIZE_T sizet_numbytesread;                  // number of bytes read
};

// default constructor
ProcessDataMiner::ProcessDataMiner(void) {
    str_procname = "";
    bool_procfound = FALSE;
    chunk = "";
}

// constructor with process name
ProcessDataMiner::ProcessDataMiner(string& proc_name) {
    str_procname = proc_name;
    bool_procfound = FALSE;
    chunk = "";

    if(findProcessId()) {
        if(!findModuleInfo(dw_procid)) {
            cerr << "Something went wrong reading module info!" << endl;
        }
    }
    else {
        cerr << "No Process with the fragment " << str_procname << " in its name could be found!" << endl;
    }
}

/**
 * @brief ProcessDataMiner::initPDM
 * @param proc_name
 *
 * This method initialized the class in case the default constructor has been used.
 * If the default constructor has been called the element <str_procname> will be
 * empty thus leading other methods to fail because needed information is missing.
 */
void ProcessDataMiner::initPDM(string& proc_name) {
    str_procname = proc_name;
    bool_procfound = FALSE;
    chunk = "";

    if(findProcessId()) {
        if(!findModuleInfo(dw_procid)) {
            cerr << "Something went wrong reading module info!" << endl;
        }
    }
    else {
        cerr << "No Process with the fragment " << str_procname << " in its name could be found!" << endl;
    }
}

// will need to be reworked if obsolete elemets will be removed
/**
 * @brief ProcessDataMiner::displayInfo
 *
 * This method briefly shows information about the initialized elements. It's useful
 * for debugging purposes.
 */
void ProcessDataMiner::displayInfo(void) {
    if(!bool_procfound) {
        cerr << "No Process could be found thus displyInfo(void) shows nothing!" << endl;
    }
    else {
        cout << "Process Name = " << str_procname << endl;
        cout << "Process ID   = " << dw_procid << endl;
        cout << "Base address = " << lpcv_baseaddress << endl;
        cout << "Base size    = " << sizet_modbasesize << endl;
    }
}


/**
 * @brief ProcessDataMiner::findProcessId
 * @return BOOL
 *
 * This method trys to find the process that contains the text fragment <str_procname>.
 * If it fails to find a process with that name the class initialization fails and you
 * cannot continue using the object.
 */
BOOL ProcessDataMiner::findProcessId(void) {
    PROCESSENTRY32 pe32;
    HANDLE hProcessSnap;

    /* as we are trying to find the process again though we already found it once
     * -> bool_procfound == TRUE -> we reset the variable so the initialization would
     * crash unexpected
     */
    if(bool_procfound) {
        bool_procfound = FALSE;
    }

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hProcessSnap == INVALID_HANDLE_VALUE) {
        cerr << "CreateToolhelp32Snapshot (of processes)" << endl;
        return( FALSE );
    }
    else {
        // Set the size of the structure before using it.
        pe32.dwSize = sizeof(PROCESSENTRY32);

        // Retrieve information about the first process, and exit if unsuccessful
        if(Process32First(hProcessSnap, &pe32) != FALSE) {
            // Now walk the snapshot of processes to the the process <str_procname>
            do {
                // convert wchar_t into string
                wchar_t* txt = pe32.szExeFile;
                wstring ws(txt);
                string str(ws.begin(),ws.end());

                if (str.find(str_procname) != string::npos) {
                    dw_procid = pe32.th32ProcessID;
                    CloseHandle(hProcessSnap);
                    return(TRUE);
                }
            } while(Process32Next(hProcessSnap, &pe32));
        }
        else {
            cerr << "Process32First" << endl;
            CloseHandle(hProcessSnap);          // clean the snapshot object
            return(FALSE);
        }
        // nothing found. close handle and return false
        CloseHandle(hProcessSnap);
        return(FALSE);
    }
}

/**
 * @brief ProcessDataMiner::getHeapInfo
 * @return BOOL
 *
 * This method creats a heaplist of the process id provided which it walks through calling the
 * method mineHeapForInfo(DWORD&, DWORD&) which it gives the heap address and size to look for.
 */
BOOL ProcessDataMiner::getHeapInfo(void) {
    HANDLE hHeapSnap;
    HEAPLIST32 hl32 = {0};
    HEAPENTRY32 he32 = {0};

    cout << chunk << endl;

    // Take a snapshot of all modules in the specified process.
    hHeapSnap = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, dw_procid);

    // if the handle is invalid return false
    if(hHeapSnap != INVALID_HANDLE_VALUE) {
        // Set the size of the structure before using it.
        hl32.dwSize = sizeof(HEAPLIST32);

        // Retrieve information about the first module, and exit if unsuccessful
        if(Heap32ListFirst(hHeapSnap, &hl32) != FALSE) {
            // Set the size of the structure before using it.
            he32.dwSize = sizeof(HEAPENTRY32);

            // Now walk the heap list of the process
            do {
                if(Heap32First(&he32, hl32.th32ProcessID, hl32.th32HeapID) != FALSE) {
                    do {
                        mineHeapForInfo(he32.dwAddress, he32.dwBlockSize);
                    } while(Heap32Next(&he32) != FALSE);
                }
                else { break; }
            } while(Heap32ListNext(hHeapSnap, &hl32) != FALSE);
        }
        else {
            cerr << "HEAP32ListFirst" << endl;
            CloseHandle(hHeapSnap);           // clean the snapshot object
            return(FALSE);
        }
    }
    else {
        cerr << "CreateToolhelp32Snapshot (of the heaplist)" << endl;
        return(FALSE);
    }

    CloseHandle(hHeapSnap);
    return(FALSE);
}

/**
 * @brief ProcessDataMiner::mineHeapForInfo
 * @param dw_address
 * @param dw_blocksize
 *
 * Provided the heap address and size it will search this resulting string for a chunk of text
 * and outputs the address of the heap where the chunk had been seen in.
 */
void ProcessDataMiner::mineHeapForInfo(DWORD& dw_address, DWORD& dw_blocksize) {
    LPBYTE pBuffer;
    BYTE byte;
    DWORD dwBytesRead, dwBlock, dwOffset;
    string text="";

    // initialize the pBuffer with the size of the current heap
    pBuffer = new BYTE[dw_blocksize];

    // read the information from the heap at dw_address with the size of dw_blocksize
    if(Toolhelp32ReadProcessMemory(dw_procid, (LPCVOID) dw_address, pBuffer, dw_blocksize, &dwBytesRead) == TRUE) {
        // read the whole heap so strings can not be cut off
        // this loop might get obsolete in future if it turns out to be useful
        for(dwBlock=0; dwBlock < dw_blocksize; dwBlock += dw_blocksize) {
            // cout << hex << dw_address + dwBlock << ";";
            for(dwOffset=0; dwOffset < dw_blocksize; dwOffset++) {
                // get the byte at the address *(pBuffer + dwBlock + dwOffset)
                byte = *(pBuffer + dwBlock + dwOffset);

                // check if printable characters
                if(32 <= byte && byte < 127) {
                    text += byte;
                }
                // if not place a '.'-character
                else {
                    text += ".";
                }
            }

            // cout << text << endl;

            // check if chunk could be found and output the address of the heap the chunk had been found in and the whole string of the heap
            if(text.find(chunk) != string::npos) {
                cout << "HeapAddress: " << hex << dw_address;
                cout << " // HeapString: " << text << endl;
            }
            // reset text
            text="";
        }
    }
}
/*****************************************************************************************************************************************************/



// might get obsolete
void ProcessDataMiner::mineForInfo(string& chunk) {
    DWORD dwBlock, dwOffset;
    BYTE byte;
    string text="";

    lpb_buffer = new BYTE[sizet_modbasesize];

    if(Toolhelp32ReadProcessMemory(dw_procid, lpcv_baseaddress, lpb_buffer, sizet_modbasesize, &sizet_numbytesread) == TRUE) {
        cout << "NumBytesRead: " << sizet_numbytesread << endl;
        for(dwBlock = 0; dwBlock < sizet_modbasesize; dwBlock+=16) {
            for(dwOffset = 0; dwOffset < 16; dwOffset++) {
                byte =*(lpb_buffer+dwBlock+dwOffset);
                if(32 <= byte && byte < 127) {
                    text+=byte;
                }
                else if(byte == '\0') {
                    text+="0";
                }
                else {
                    text+=".";
                }
            }
            if(text.find(chunk) != string::npos) {

                cout << "Address: " << hex << *(lpb_buffer + dwBlock);
                cout << " // String: " << text << endl;
            }
            // reset text
            text="";
        }
    }
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
     * -> bool_procfound == TRUE -> we reset the variable so the initialization would crash unexpected
     */
    if(bool_procfound) {
        bool_procfound = FALSE;
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

    // Now walk the module list of the process to find the module <str_procname>
    do {
        // convert wchar_t into string
        wchar_t* txt = me32.szExePath;
        wstring ws(txt);
        string exe_path(ws.begin(),ws.end());

        if (exe_path.find(str_procname) != string::npos) {
            lpcv_baseaddress = me32.modBaseAddr;
            sizet_modbasesize = me32.modBaseSize;
            bool_procfound = TRUE;
            CloseHandle(hModuleSnap);
            return(TRUE);
        }
    } while(Module32Next(hModuleSnap, &me32));

    CloseHandle(hModuleSnap);
    return(FALSE);
}


#endif // PROCESSDATAMINER_H
