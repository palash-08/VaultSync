#include "native_host/NativeHost.h"

#include <iostream>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

int main() {
#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif

    std::ios_base::sync_with_stdio(false);

    NativeHost host;
    host.run(std::cin, std::cout);

    return 0;
}
