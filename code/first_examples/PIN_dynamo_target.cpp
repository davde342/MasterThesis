#include <iostream>
#include <cstdlib>

int main(int argc, char* argv[]) {
    int secret = 42;
    int guess = (argc > 1) ? std::atoi(argv[1]) : 0;

    if (guess == secret) {
        std::cout << "Branch A: You guessed it!" << std::endl;
    } else {
        std::cout << "Branch B: Wrong guess." << std::endl;
    }
    
    return 0;
}