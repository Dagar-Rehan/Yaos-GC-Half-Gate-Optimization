#pragma once

#include <chrono>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/dsa.h>
#include <crypto++/elgamal.h>
#include <crypto++/files.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>
#include <crypto++/hkdf.h>
#include <crypto++/hmac.h>
#include <crypto++/integer.h>
#include <crypto++/modes.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>
#include <crypto++/rijndael.h>
#include <crypto++/sha.h>

#include "../../include-shared/messages.hpp"
#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/network_driver.hpp"

class OTDriver {
public:
  OTDriver(std::shared_ptr<NetworkDriver> network_driver,
           std::shared_ptr<CryptoDriver> crypto_driver,
           std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);

  void OT_send(std::string m0, std::string m1);
  std::string OT_recv(int choice_bit);

private:
  std::shared_ptr<CryptoDriver> crypto_driver;
  std::shared_ptr<NetworkDriver> network_driver;
  std::shared_ptr<CLIDriver> cli_driver;

  CryptoPP::SecByteBlock AES_key;
  CryptoPP::SecByteBlock HMAC_key;
};
