#include "processdataminer.h"
#include <string>
#include <ctime>

using namespace std;

int main(void) {
    string seed = "Patrizier", chunk;
    ProcessDataMiner PDM(seed);

    time_t now = time(0);
    char* dt = ctime(&now);
    cout << dt << endl;

    PDM.chunk = "Stockholm";
    PDM.getHeapInfo();

    now = time(0);
    dt = ctime(&now);
    cout << dt << endl;


    //PDM.displayInfo();
    //chunk = "Stockholm";
    //PDM.mineForInfo(chunk);
}

