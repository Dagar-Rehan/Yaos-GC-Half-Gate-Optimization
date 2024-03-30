#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include "../../include-shared/circuit.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/pkg/evaluator.hpp"

/*
 * Usage: ./yaos_evaluator <circuit file> <input file> <address> <port>
 */
int main(int argc, char *argv[]) {
  // Initialize logger
  initLogger(logging::trivial::severity_level::trace);

  // Parse args
  if (!(argc == 5)) {
    std::cout << "Usage: ./yaos_evaluator <circuit file> <input file> "
                 "<address> <port>"
              << std::endl;
    return 1;
  }
  std::string circuit_file = argv[1];
  std::string input_file = argv[2];
  std::string address = argv[3];
  int port = atoi(argv[4]);

  // Parse circuit.
  Circuit circuit = parse_circuit(circuit_file);

  // Parse input.
  std::vector<int> input = parse_input(input_file);

  // Connect to network driver.
  std::shared_ptr<NetworkDriver> network_driver =
      std::make_shared<NetworkDriverImpl>();
  network_driver->connect(address, port);
  std::shared_ptr<CryptoDriver> crypto_driver =
      std::make_shared<CryptoDriver>();

  // Create garbler then run.
  EvaluatorClient evaluator =
      EvaluatorClient(circuit, network_driver, crypto_driver);
  evaluator.run(input);
  return 0;
}
