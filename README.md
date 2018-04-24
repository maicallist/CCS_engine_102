# CCS Engine

## Getting Started

CCS_Engine is a demonstration project to show people **'How to create your own OpenSSL engine'**.

CCS_Engine implements:
  
* SM2 (ec based crypto system)
* SM3 (message digest)
* SM4 (feistel cipher) 

above algorithms are not available in version 1.0.2(see OpenSSL 1.1.1).

**Do not** use this project directly, as it provides no security guarantee and algorithms implemented in this engine have no optimization at all, thus suffer from horrible performance issues.

If you ever need algorithms not yet provided in any cryptographic libraries, consider implement them via OpenSSL engine, with caution.

## Documentation

see doc/ccs\_engine\_dev.md for detailed walk through.

## OpenSSL Version

OpenSSL 1.0.2 required for this demo

## Built With

* Clang 3.4.2
* Make 3.82
* CentOS 7.4.1708

## Usage
TBA

## License
This project is licensed under the GPLv3 License - see the COPYING file for details
