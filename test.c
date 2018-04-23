#include <stdio.h>
#include <openssl/opensslv.h>

int
main()
{
    printf("We're using OpenSSL %s.\n", OPENSSL_VERSION_TEXT);
    return 0;
}