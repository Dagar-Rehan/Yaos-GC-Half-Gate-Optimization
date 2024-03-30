#include <algorithm>
#include <crypto++/misc.h>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/pkg/garbler.hpp"

/*
Syntax to use logger:
  CUSTOM_LOG(lg, debug) << "your message"
See logger.hpp for more modes besides 'debug'
*/
namespace {
src::severity_logger<logging::trivial::severity_level> lg;
}

/**
 * Constructor. Note that the OT_driver is left uninitialized.
 */
GarblerClient::GarblerClient(Circuit circuit,
                             std::shared_ptr<NetworkDriver> network_driver,
                             std::shared_ptr<CryptoDriver> crypto_driver) {
  this->circuit = circuit;
  this->network_driver = network_driver;
  this->crypto_driver = crypto_driver;
  this->cli_driver = std::make_shared<CLIDriver>();
  initLogger(logging::trivial::severity_level::trace);
}

/**
 * Handle key exchange with evaluator
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
GarblerClient::HandleKeyExchange() {
  // Generate private/public DH keys
  auto dh_values = this->crypto_driver->DH_initialize();

  // Send g^b
  DHPublicValue_Message garbler_public_value_s;
  garbler_public_value_s.public_value = std::get<2>(dh_values);
  std::vector<unsigned char> garbler_public_value_data;
  garbler_public_value_s.serialize(garbler_public_value_data);
  network_driver->send(garbler_public_value_data);

  // Listen for g^a
  std::vector<unsigned char> evaluator_public_value_data =
      network_driver->read();
  DHPublicValue_Message evaluator_public_value_s;
  evaluator_public_value_s.deserialize(evaluator_public_value_data);

  // Recover g^ab
  CryptoPP::SecByteBlock DH_shared_key = crypto_driver->DH_generate_shared_key(
      std::get<0>(dh_values), std::get<1>(dh_values),
      evaluator_public_value_s.public_value);
  CryptoPP::SecByteBlock AES_key =
      this->crypto_driver->AES_generate_key(DH_shared_key);
  CryptoPP::SecByteBlock HMAC_key =
      this->crypto_driver->HMAC_generate_key(DH_shared_key);
  auto keys = std::make_pair(AES_key, HMAC_key);
  this->ot_driver =
      std::make_shared<OTDriver>(network_driver, crypto_driver, keys);
  return keys;
}

/**
 * run. This function should:
 * 1) Generate a garbled circuit from the given circuit in this->circuit
 * 2) Send the garbled circuit to the evaluator
 * 3) Send garbler's input labels to the evaluator
 * 4) Send evaluator's input labels using OT
 * 5) Receive final labels, and use this to get the final output
 * `input` is the garbler's input for each gate
 * Final output should be a string containing only "0"s or "1"s
 * Throw errors only for invalid MACs
 */
std::string GarblerClient::run(std::vector<int> input) {
  // Key exchange
  auto keys = this->HandleKeyExchange();

  // TODO: implement me!
}

/**
 * Generate garbled gates for the circuit by encrypting each entry.
 * You may find `std::random_shuffle` useful
 */
std::vector<GarbledGate> GarblerClient::generate_gates(Circuit circuit,
                                                       GarbledLabels labels) {
  // TODO: implement me!
  std::vector<GarbledGate> all_garbled_gates;

  for (int current_gate_num = 0; current_gate_num < circuit.num_gate; current_gate_num++) {
    Gate current_gate = circuit.gates.at(current_gate_num);

    GarbledGate garbled_gate;
    if (current_gate.type == GateType::AND_GATE) {
      garbled_gate.entries.push_back(
      this->encrypt_label(labels.zeros.at(current_gate.lhs), labels.zeros.at(current_gate.rhs), labels.zeros.at(current_gate.output))
      );
      garbled_gate.entries.push_back(
      this->encrypt_label(labels.zeros.at(current_gate.lhs), labels.ones.at(current_gate.rhs), labels.zeros.at(current_gate.output))
      );
      garbled_gate.entries.push_back(
      this->encrypt_label(labels.ones.at(current_gate.lhs), labels.zeros.at(current_gate.rhs), labels.zeros.at(current_gate.output))
      );
      garbled_gate.entries.push_back(
      this->encrypt_label(labels.ones.at(current_gate.lhs), labels.ones.at(current_gate.rhs), labels.ones.at(current_gate.output))
      );
    } else if (current_gate.type == GateType::XOR_GATE) {
      garbled_gate.entries.push_back(
      this->encrypt_label(labels.zeros.at(current_gate.lhs), labels.zeros.at(current_gate.rhs), labels.zeros.at(current_gate.output))
      );
      garbled_gate.entries.push_back(
      this->encrypt_label(labels.zeros.at(current_gate.lhs), labels.ones.at(current_gate.rhs), labels.ones.at(current_gate.output))
      );
      garbled_gate.entries.push_back(
      this->encrypt_label(labels.ones.at(current_gate.lhs), labels.zeros.at(current_gate.rhs), labels.ones.at(current_gate.output))
      );
      garbled_gate.entries.push_back(
      this->encrypt_label(labels.ones.at(current_gate.lhs), labels.ones.at(current_gate.rhs), labels.zeros.at(current_gate.output))
      );
    } else {
      GarbledWire rhs_dummy;
      rhs_dummy.value = DUMMY_RHS;

      garbled_gate.entries.push_back(
      this->encrypt_label(labels.zeros.at(current_gate.lhs), rhs_dummy, labels.ones.at(current_gate.output))
      );
      garbled_gate.entries.push_back(
      this->encrypt_label(labels.ones.at(current_gate.lhs), rhs_dummy, labels.zeros.at(current_gate.output))
      );
    }

    std::random_shuffle(garbled_gate.entries.begin(), garbled_gate.entries.end());
    all_garbled_gates.push_back(garbled_gate);
  }

  return all_garbled_gates;
}

/**
 * Generate labels for *every* wire in the circuit.
 * To generate an individual label, use `generate_label`.
 */
GarbledLabels GarblerClient::generate_labels(Circuit circuit) {
  // TODO: implement me!
  GarbledLabels circuit_labels;
  for (int i = 0; i < circuit.num_wire; i++) {
    GarbledWire g0;
    g0.value = this->generate_label();
    circuit_labels.zeros.push_back(g0);

    GarbledWire g1;
    g1.value = this->generate_label();
    circuit_labels.ones.push_back(g1);
  }

  return circuit_labels;
}

/**
 * Generate the encrypted label given the lhs, rhs, and output of that gate.
 * Remember to tag LABEL_TAG_LENGTH trailing 0s to end before encrypting.
 * You may find CryptoDriver::hash_inputs, CryptoPP::SecByteBlock::CleanGrow,
 * and CryptoPP::xorbuf useful.
 */
CryptoPP::SecByteBlock GarblerClient::encrypt_label(GarbledWire lhs,
                                                    GarbledWire rhs,
                                                    GarbledWire output) {
  // TODO: implement me!
  SecByteBlock output_val = output.value;
  output_val.CleanGrow(LABEL_LENGTH + LABEL_TAG_LENGTH);

  CryptoPP::SecByteBlock hash = this->crypto_driver->hash_inputs(lhs.value, rhs.value);

  CryptoPP::xorbuf(hash, output_val, output_val.size());

  return hash;
}

/**
 * Generate label.
 */
CryptoPP::SecByteBlock GarblerClient::generate_label() {
  CryptoPP::SecByteBlock label(LABEL_LENGTH);
  CryptoPP::OS_GenerateRandomBlock(false, label, label.size());
  return label;
}

/*
 * Given a set of 0/1 labels and an input vector of 0's and 1's, returns the
 * labels corresponding to the inputs starting at begin.
 */
std::vector<GarbledWire>
GarblerClient::get_garbled_wires(GarbledLabels labels, std::vector<int> input,
                                 int begin) {
  std::vector<GarbledWire> res;
  for (int i = 0; i < input.size(); i++) {
    switch (input[i]) {
    case 0:
      res.push_back(labels.zeros[begin + i]);
      break;
    case 1:
      res.push_back(labels.ones[begin + i]);
      break;
    default:
      std::cerr << "INVALID INPUT CHARACTER" << std::endl;
    }
  }
  return res;
}
