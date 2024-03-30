#pragma once

#include "../../include-shared/circuit.hpp"
#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/network_driver.hpp"
#include "../../include/drivers/ot_driver.hpp"

class EvaluatorClient {
public:
  EvaluatorClient(Circuit circuit,
                  std::shared_ptr<NetworkDriver> network_driver,
                  std::shared_ptr<CryptoDriver> crypto_driver);
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> HandleKeyExchange();
  std::string run(std::vector<int> input);
  GarbledWire evaluate_gate(GarbledGate gate, GarbledWire lhs, GarbledWire rhs);
  bool verify_decryption(CryptoPP::SecByteBlock decryption);
  CryptoPP::SecByteBlock snip_decryption(CryptoPP::SecByteBlock decryption);

private:
  Circuit circuit;
  std::shared_ptr<NetworkDriver> network_driver;
  std::shared_ptr<CryptoDriver> crypto_driver;
  std::shared_ptr<OTDriver> ot_driver;
  std::shared_ptr<CLIDriver> cli_driver;
};
