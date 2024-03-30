#include "../../include/pkg/evaluator.hpp"
#include "../../include-shared/constants.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/util.hpp"

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
EvaluatorClient::EvaluatorClient(Circuit circuit,
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
EvaluatorClient::HandleKeyExchange() {
  // Generate private/public DH keys
  auto dh_values = this->crypto_driver->DH_initialize();

  // Listen for g^b
  std::vector<unsigned char> garbler_public_value_data = network_driver->read();
  DHPublicValue_Message garbler_public_value_s;
  garbler_public_value_s.deserialize(garbler_public_value_data);

  // Send g^a
  DHPublicValue_Message evaluator_public_value_s;
  evaluator_public_value_s.public_value = std::get<2>(dh_values);
  std::vector<unsigned char> evaluator_public_value_data;
  evaluator_public_value_s.serialize(evaluator_public_value_data);
  network_driver->send(evaluator_public_value_data);

  // Recover g^ab
  CryptoPP::SecByteBlock DH_shared_key = crypto_driver->DH_generate_shared_key(
      std::get<0>(dh_values), std::get<1>(dh_values),
      garbler_public_value_s.public_value);
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
 * 1) Receive the garbled circuit and the garbler's input
 * 2) Reconstruct the garbled circuit and input the garbler's inputs
 * 3) Retrieve evaluator's inputs using OT
 * 4) Evaluate gates in order (use `evaluate_gate` to help!)
 * 5) Send final labels to the garbler
 * 6) Receive final output
 * `input` is the evaluator's input for each gate
 * You may find `resize` useful before running OT
 * You may also find `string_to_byteblock` useful for converting OT output to
 * wires Disconnect and throw errors only for invalid MACs
 */
std::string EvaluatorClient::run(std::vector<int> input) {
  // Key exchange
  auto keys = this->HandleKeyExchange();

  // TODO: implement me!
  //throw std::runtime_error("EvaluatorClient::run - Testing!!!");
  std::pair<std::vector<unsigned char>, bool> intermediate;

  //get the garbled circuit
  intermediate = this->crypto_driver->decrypt_and_verify(std::get<0>(keys), std::get<1>(keys), this->network_driver->read());
  if (std::get<1>(intermediate) == false) {
    throw std::runtime_error("EvaluatorClient::run - HMAC failed for garbled circuit.");
  }
  GarblerToEvaluator_GarbledTables_Message garbled_circuit_msg;
  garbled_circuit_msg.deserialize(std::get<0>(intermediate));

  //get garbled inputs
  intermediate = this->crypto_driver->decrypt_and_verify(std::get<0>(keys), std::get<1>(keys), this->network_driver->read());
  if (std::get<1>(intermediate) == false) {
    throw std::runtime_error("EvaluatorClient::run - HMAC failed for garbled inputs from garbler.");
  }
  GarblerToEvaluator_GarblerInputs_Message garbled_inputs_msg;
  garbled_inputs_msg.deserialize(std::get<0>(intermediate));

  //set the gate and inputs from the garbler to their own variables
  std::vector<GarbledGate> garbled_circuit = garbled_circuit_msg.garbled_tables;
  std::vector<GarbledWire> garblers_inputs = garbled_inputs_msg.garbler_inputs;

  //use OT to get our garbled input labels
  std::vector<GarbledWire> my_inputs_from_garbler;
  for (int i = 0; i < input.size(); i++) {
    GarbledWire wire;
    wire.value = string_to_byteblock(this->ot_driver->OT_recv(input.at(i)));
    my_inputs_from_garbler.push_back(wire);
  }

  //evaulate the circuit
  std::vector<GarbledWire> merged(garblers_inputs);
  merged.insert(merged.end(), my_inputs_from_garbler.begin(), my_inputs_from_garbler.end());
   
  for (int i = 0; i < garbled_circuit.size(); i++) {
    GarbledGate current_gate_garbled = garbled_circuit.at(i);
    Gate current_gate = this->circuit.gates.at(i);

    if (current_gate.type == GateType::AND_GATE || current_gate.type == GateType::XOR_GATE) {
      GarbledWire lhs = merged.at(current_gate.lhs);
      GarbledWire rhs = merged.at(current_gate.rhs);
      GarbledWire output = evaluate_gate(current_gate_garbled, lhs, rhs); 
      merged.push_back(output);
    } else {
      GarbledWire lhs = merged.at(current_gate.lhs);
      GarbledWire rhs;
      rhs.value = DUMMY_RHS;
      GarbledWire output = evaluate_gate(current_gate_garbled, lhs, rhs); 
      merged.push_back(output);
    }
  }

  //get the output labels
  std::vector<GarbledWire> output_labels;
  //for (int i = (this->circuit.num_wire - this->circuit.output_length); i < this->circuit.num_wire; i++) {
    //output_labels.push_back(merged.at(i));
  //}

  //send output labels back to evaulator
  EvaluatorToGarbler_FinalLabels_Message output_labels_msg;
  output_labels_msg.final_labels = output_labels;
  this->network_driver->send(this->crypto_driver->encrypt_and_tag(std::get<0>(keys), std::get<1>(keys), &output_labels_msg));

  //get back result
  intermediate = this->crypto_driver->decrypt_and_verify(std::get<0>(keys), std::get<1>(keys), this->network_driver->read());
  if (std::get<1>(intermediate) == false) {
    throw std::runtime_error("EvaluatorClient::run - HMAC failed for output from garbler.");
  }
  GarblerToEvaluator_FinalOutput_Message final_output_msg;
  final_output_msg.deserialize(std::get<0>(intermediate));

  return final_output_msg.final_output;
}

/**
 * Evaluate gate.
 * You may find CryptoPP::xorbuf and CryptoDriver::hash_inputs useful.
 * To determine if a decryption is valid, use verify_decryption.
 * To retrieve the label from a decryption, use snip_decryption.
 */
GarbledWire EvaluatorClient::evaluate_gate(GarbledGate gate, GarbledWire lhs,
                                           GarbledWire rhs) {
  // TODO: implement me!
  GarbledWire output;

  for (int i = 0; i < gate.entries.size(); i++) {
    CryptoPP::SecByteBlock cipher = gate.entries.at(i);

    CryptoPP::SecByteBlock hash = this->crypto_driver->hash_inputs(lhs.value, rhs.value);

    CryptoPP::xorbuf(cipher, hash, cipher.size());

    if (verify_decryption(cipher)) {
      output.value = snip_decryption(cipher);
      return output;
    }
  }

  return output;
}

/**
 * Verify decryption. A valid dec should end with LABEL_TAG_LENGTH bits of 0s.
 */
bool EvaluatorClient::verify_decryption(CryptoPP::SecByteBlock decryption) {
  CryptoPP::SecByteBlock trail(decryption.data() + LABEL_LENGTH,
                               LABEL_TAG_LENGTH);
  return byteblock_to_integer(trail) == CryptoPP::Integer::Zero();
}

/**
 * Returns the first LABEL_LENGTH bits of a decryption.
 */
CryptoPP::SecByteBlock
EvaluatorClient::snip_decryption(CryptoPP::SecByteBlock decryption) {
  CryptoPP::SecByteBlock head(decryption.data(), LABEL_LENGTH);
  return head;
}
