#include <windows.h>
#include <iostream>

int main() {
    std::cout << "PID: " << GetCurrentProcessId() << std::endl;
    
    while (true) {
        std::cin.get();
        
        int result = MessageBoxW(NULL, L"This is the original text.", L"Original Caption", MB_OK);
        
        if (result == IDOK) {
            std::cout << "Target received: IDOK (User clicked OK)\n" << std::endl;
        } else if (result == IDYES) {
            std::cout << "Target received: IDYES (User clicked YES)\n" << std::endl;
        } else if (result == IDNO) {
            std::cout << "Target received: IDNO (User clicked NO)\n" << std::endl;
        } else {
            std::cout << "Target received: " << result << "\n" << std::endl;
        }
    }
    return 0;
}
