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
  std::pair<std::vector<unsigned char>, bool> intermediate;

  //######################################## NEW #########################################

  //generate universal R value for the free XORs
  SecByteBlock R = generate_label();
  if(byteblock_to_integer(R).GetBit(0) == 0) {
    SecByteBlock one(integer_to_byteblock(Integer::Zero()));
    one.CleanGrow(R.size());
    *(one.end() - 1) = 1;
    CryptoPP::xorbuf(R, one, one.size());
  }

  //generate the garbled circuit and the garbled tags
  GarbledLabels input_labels = this->generate_labels_input_wires(this->circuit, R);
  std::vector<GarbledGate> garbled_circuit = this->generate_gates(this->circuit, input_labels, R);

  //send garbled table
  GarblerToEvaluator_GarbledTables_Message gc_msg;
  gc_msg.garbled_tables = garbled_circuit;
  this->network_driver->send(this->crypto_driver->encrypt_and_tag(std::get<0>(keys), std::get<1>(keys), &gc_msg));

  //get the input labels for the garbler
  std::vector<GarbledWire> garbler_inputs;
  for (int i = 0; i < input.size(); i++) {
    if (input.at(i) == 0) {
      garbler_inputs.push_back(input_labels.zeros.at(i));
    } else {
      garbler_inputs.push_back(input_labels.ones.at(i));
    }
  }

  //send garblers input labels over
  GarblerToEvaluator_GarblerInputs_Message garbler_inputs_msg;
  garbler_inputs_msg.garbler_inputs = garbler_inputs;
  this->network_driver->send(this->crypto_driver->encrypt_and_tag(std::get<0>(keys), std::get<1>(keys), &garbler_inputs_msg));

  //send evaulators input labels
  for (int i = 0; i < this->circuit.evaluator_input_length; i++) {
    this->ot_driver->OT_send(byteblock_to_string(input_labels.zeros.at(this->circuit.garbler_input_length + i).value), byteblock_to_string(input_labels.ones.at(this->circuit.garbler_input_length + i).value));
  }

  //get the output labels from the evaulator
  intermediate = this->crypto_driver->decrypt_and_verify(std::get<0>(keys), std::get<1>(keys), this->network_driver->read());
  if (std::get<1>(intermediate) == false) {
    throw std::runtime_error("GarblerClient::run - HMAC failed for final output labels.");
  }
  EvaluatorToGarbler_FinalLabels_Message output_labels_msg;
  output_labels_msg.deserialize(std::get<0>(intermediate));

  std::string output_string = "";
  for (int i = 0; i < output_labels_msg.final_labels.size(); i++) {
    GarbledWire current_label = output_labels_msg.final_labels.at(i);

    bool is_zero = false;
    bool lsb_1 = byteblock_to_integer(input_labels.zeros.at(circuit.num_wire - circuit.output_length + i).value).GetBit(0);
    bool lsb_2 = byteblock_to_integer(current_label.value).GetBit(0);
    output_string = output_string + std::to_string(lsb_1 ^ lsb_2);
  }

  //send final output to evaulator
  GarblerToEvaluator_FinalOutput_Message final_output_msg;
  final_output_msg.final_output = output_string;
    this->network_driver->send(this->crypto_driver->encrypt_and_tag(std::get<0>(keys), std::get<1>(keys), &final_output_msg));

  return output_string;
}

/**
 * Generate garbled gates for the circuit by encrypting each entry.
 * You may find `std::random_shuffle` useful
 */
std::vector<GarbledGate> GarblerClient::generate_gates(Circuit circuit,
                                                       GarbledLabels &labels, SecByteBlock R) {
  // TODO: implement me!
  std::vector<GarbledGate> all_garbled_gates;

  for (int current_gate_num = 0; current_gate_num < circuit.num_gate; current_gate_num++) {
    Gate current_gate = circuit.gates.at(current_gate_num);
    GarbledWire new_zero_label;
    GarbledGate garbled_gate;

    if (current_gate.type == GateType::AND_GATE) {
      std::tuple<GarbledWire, CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> W0_Tg_Te = this->GbAnd(labels.zeros.at(current_gate.lhs), labels.ones.at(current_gate.lhs), labels.zeros.at(current_gate.rhs), labels.ones.at(current_gate.rhs), R);
      new_zero_label = std::get<0>(W0_Tg_Te);
      garbled_gate.entries.push_back(std::get<1>(W0_Tg_Te));
      garbled_gate.entries.push_back(std::get<2>(W0_Tg_Te));

    } else if (current_gate.type == GateType::XOR_GATE) {
      new_zero_label.value = labels.zeros.at(current_gate.lhs).value;
      CryptoPP::xorbuf(new_zero_label.value, labels.zeros.at(current_gate.rhs).value, new_zero_label.value.size());
      
    } else {
      GarbledWire rhs_dummy;
      rhs_dummy.value = DUMMY_RHS;

      GarbledWire lhs_not_zero = labels.zeros.at(current_gate.lhs);
      GarbledWire lhs_not_one = labels.ones.at(current_gate.lhs);
      bool permbit = byteblock_to_integer(lhs_not_zero.value).GetBit(0);

      new_zero_label.value = this->generate_label();

      GarbledWire new_zero_label_temp = new_zero_label;
      GarbledWire new_one_label_temp = new_zero_label;
      CryptoPP::xorbuf(new_one_label_temp.value, R, new_one_label_temp.value.size());

      CryptoPP::xorbuf(new_one_label_temp.value, this->crypto_driver->hash_inputs(lhs_not_zero.value, rhs_dummy.value), new_one_label_temp.value.size());
      CryptoPP::xorbuf(new_zero_label_temp.value, this->crypto_driver->hash_inputs(lhs_not_one.value, rhs_dummy.value), new_zero_label_temp.value.size());

      if(permbit == 0) {
        garbled_gate.entries.push_back(new_one_label_temp.value);
        garbled_gate.entries.push_back(new_zero_label_temp.value);
      } else {
        garbled_gate.entries.push_back(new_zero_label_temp.value);
        garbled_gate.entries.push_back(new_one_label_temp.value);
      }

    }

    GarbledWire new_one_label = new_zero_label;
    CryptoPP::xorbuf(new_one_label.value, R, new_one_label.value.size());
    labels.zeros.at(current_gate.output) = new_zero_label;
    labels.ones.at(current_gate.output) = new_one_label;
    all_garbled_gates.push_back(garbled_gate);
  }

  return all_garbled_gates;
}

/**
 * Generate labels for *every* wire in the circuit.
 * To generate an individual label, use `generate_label`.
 */
GarbledLabels GarblerClient::generate_labels_input_wires(Circuit circuit, SecByteBlock R) {
  // TODO: implement me!
  GarbledLabels circuit_labels;
  circuit_labels.zeros.resize(circuit.num_wire);
  circuit_labels.ones.resize(circuit.num_wire);

  for (int i = 0; i < circuit.garbler_input_length + circuit.evaluator_input_length; i++) {
    GarbledWire g0;
    g0.value = this->generate_label();
    circuit_labels.zeros.at(i) = g0;

    GarbledWire g1;
    g1.value = g0.value;
    CryptoPP::xorbuf(g1.value, R, R.size());
    circuit_labels.ones.at(i) = g1;
  }

  return circuit_labels;
}

/**
 * Generate the encrypted label given the lhs, rhs, and output of that gate.
 * Remember to tag LABEL_TAG_LENGTH trailing 0s to end before encrypting.
 * You may find CryptoDriver::hash_inputs, CryptoPP::SecByteBlock::CleanGrow,
 * and CryptoPP::xorbuf useful.
 */
std::tuple<GarbledWire, CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> GarblerClient::GbAnd(GarbledWire lhs_0, GarbledWire lhs_1,
                                                    GarbledWire rhs_0, GarbledWire rhs_1,
                                                    SecByteBlock R) {
  // TODO: implement me!
  static unsigned long pad = 0;

  bool permbit_lhs = byteblock_to_integer(lhs_0.value).GetBit(0);
  bool permbit_rhs = byteblock_to_integer(rhs_0.value).GetBit(0);

  pad = pad + 1;

  SecByteBlock padding(integer_to_byteblock(Integer(pad)));
  padding.CleanGrow(lhs_0.value.size());

  //first half gate
  SecByteBlock Tg = this->crypto_driver->hash_inputs(lhs_0.value, padding);
  SecByteBlock Wg0 = Tg;
  CryptoPP::xorbuf(Tg, this->crypto_driver->hash_inputs(lhs_1.value, padding), Tg.size());
  if (permbit_rhs) {
    CryptoPP::xorbuf(Tg, R, Tg.size());
  }
  if (permbit_lhs) {
    CryptoPP::xorbuf(Wg0, Tg, Tg.size());
  }

  pad = pad + 1;

  padding = SecByteBlock(integer_to_byteblock(Integer(pad)));
  padding.CleanGrow(lhs_0.value.size());

  //second half gate
  SecByteBlock Te = this->crypto_driver->hash_inputs(rhs_0.value, padding);
  SecByteBlock We0 = Te;
  CryptoPP::xorbuf(Te, this->crypto_driver->hash_inputs(rhs_1.value, padding), Te.size());
  CryptoPP::xorbuf(Te, lhs_0.value, Te.size());
  if (permbit_rhs) {
    SecByteBlock TeTemp = Te;
    CryptoPP::xorbuf(TeTemp, lhs_0.value, TeTemp.size());
    CryptoPP::xorbuf(We0, TeTemp, Wg0.size());
  }

  GarbledWire W0;
  W0.value = Wg0;
  CryptoPP::xorbuf(W0.value, We0, W0.value.size());

  return std::make_tuple(W0, Tg, Te);
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
