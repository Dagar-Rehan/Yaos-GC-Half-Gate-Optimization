#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include "../../include-shared/circuit.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/pkg/garbler.hpp"

/*
 * Usage: ./ot_test <address> <port> [send <m0> <m1>] [receive <b>]
 */
int main(int argc, char *argv[]) {
  // Initialize logger
  initLogger(logging::trivial::severity_level::trace);

  // Parse args
  if (!(argc == 5 || argc == 6)) {
    std::cout << "./ot_test <address> <port> [send <m0> <m1>] [receive <b>]"
              << std::endl;
    return 1;
  }
  std::string address = argv[1];
  int port = atoi(argv[2]);
  std::string choice = argv[3];

  // Check choice...
  if (choice == "send") {
    // Set up sender.
    std::shared_ptr<NetworkDriver> network_driver =
        std::make_shared<NetworkDriverImpl>();
    network_driver->listen(port);
    std::shared_ptr<CryptoDriver> crypto_driver =
        std::make_shared<CryptoDriver>();

    // Key exchange
    auto dh = crypto_driver->DH_initialize();
    network_driver->send(str2chvec(byteblock_to_string(std::get<2>(dh))));
    CryptoPP::SecByteBlock dh_other =
        string_to_byteblock(chvec2str(network_driver->read()));
    CryptoPP::SecByteBlock dh_secret = crypto_driver->DH_generate_shared_key(
        std::get<0>(dh), std::get<1>(dh), dh_other);
    CryptoPP::SecByteBlock AES_key = crypto_driver->AES_generate_key(dh_secret);
    CryptoPP::SecByteBlock HMAC_key =
        crypto_driver->HMAC_generate_key(dh_secret);
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys =
        std::make_pair(AES_key, HMAC_key);

    // Send OT!
    std::string m0 = argv[4];
    std::string m1 = argv[5];
    OTDriver ot_driver(network_driver, crypto_driver, keys);
    ot_driver.OT_send(m0, m1);
  } else if (choice == "receive") {
    // Set up receiver.
    std::shared_ptr<NetworkDriver> network_driver =
        std::make_shared<NetworkDriverImpl>();
    network_driver->connect(address, port);
    std::shared_ptr<CryptoDriver> crypto_driver =
        std::make_shared<CryptoDriver>();

    // Key exchange
    auto dh = crypto_driver->DH_initialize();
    CryptoPP::SecByteBlock dh_other =
        string_to_byteblock(chvec2str(network_driver->read()));
    network_driver->send(str2chvec(byteblock_to_string(std::get<2>(dh))));
    CryptoPP::SecByteBlock dh_secret = crypto_driver->DH_generate_shared_key(
        std::get<0>(dh), std::get<1>(dh), dh_other);
    CryptoPP::SecByteBlock AES_key = crypto_driver->AES_generate_key(dh_secret);
    CryptoPP::SecByteBlock HMAC_key =
        crypto_driver->HMAC_generate_key(dh_secret);
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys =
        std::make_pair(AES_key, HMAC_key);

    // Send OT!
    int b = atoi(argv[4]);
    OTDriver ot_driver(network_driver, crypto_driver, keys);
    std::string res = ot_driver.OT_recv(b);
    std::cout << "Received: \"" << res << "\"" << std::endl;
  } else {
    // If invalid choice, exit.
    std::cout << "./ot_test <address> <port> [send <m0> <m1>] [receive <b>]"
              << std::endl;
    return 1;
  }
  return 0;
}
