#pragma once

#include "../../include-shared/circuit.hpp"
#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/network_driver.hpp"
#include "../../include/drivers/ot_driver.hpp"

class GarblerClient {
public:
  GarblerClient(Circuit circuit, std::shared_ptr<NetworkDriver> network_driver,
                std::shared_ptr<CryptoDriver> crypto_driver);
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> HandleKeyExchange();
  std::string run(std::vector<int> input);
  GarbledLabels generate_labels_input_wires(Circuit circuit, SecByteBlock R);
  std::vector<GarbledGate> generate_gates(Circuit circuit,
                                          GarbledLabels &labels, SecByteBlock R, GarbledWire dummy_rhs_xor_not);
  std::tuple<GarbledWire, CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> GbAnd(GarbledWire lhs_0, GarbledWire lhs_1, GarbledWire rhs_0, GarbledWire rhs_1,
                                       SecByteBlock R);
  CryptoPP::SecByteBlock generate_label();
  std::vector<GarbledWire> get_garbled_wires(GarbledLabels labels,
                                             std::vector<int> input, int begin);

private:
  Circuit circuit;
  std::shared_ptr<NetworkDriver> network_driver;
  std::shared_ptr<CryptoDriver> crypto_driver;
  std::shared_ptr<OTDriver> ot_driver;
  std::shared_ptr<CLIDriver> cli_driver;
};
