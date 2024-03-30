#include "../include-shared/messages.hpp"
#include "../include-shared/util.hpp"

// ================================================
// MESSAGE TYPES
// ================================================

/**
 * Get message type.
 */
MessageType::T get_message_type(std::vector<unsigned char> &data) {
  return (MessageType::T)data[0];
}

// ================================================
// SERIALIZERS
// ================================================

/**
 * Puts the bool b into the end of data.
 */
int put_bool(bool b, std::vector<unsigned char> &data) {
  data.push_back((char)b);
  return 1;
}

/**
 * Puts the string s into the end of data.
 */
int put_string(std::string s, std::vector<unsigned char> &data) {
  // Put length
  int idx = data.size();
  data.resize(idx + sizeof(size_t));
  size_t str_size = s.size();
  std::memcpy(&data[idx], &str_size, sizeof(size_t));

  // Put string
  data.insert(data.end(), s.begin(), s.end());
  return data.size() - idx;
}

/**
 * Puts the integer i into the end of data.
 */
int put_integer(CryptoPP::Integer i, std::vector<unsigned char> &data) {
  return put_string(CryptoPP::IntToString(i), data);
}

/**
 * Puts the nest bool from data at index idx into b.
 */
int get_bool(bool *b, std::vector<unsigned char> &data, int idx) {
  *b = (bool)data[idx];
  return 1;
}

/**
 * Puts the nest string from data at index idx into s.
 */
int get_string(std::string *s, std::vector<unsigned char> &data, int idx) {
  // Get length
  size_t str_size;
  std::memcpy(&str_size, &data[idx], sizeof(size_t));

  // Get string
  std::vector<unsigned char> svec(&data[idx + sizeof(size_t)],
                                  &data[idx + sizeof(size_t) + str_size]);
  *s = chvec2str(svec);
  return sizeof(size_t) + str_size;
}

/**
 * Puts the next integer from data at index idx into i.
 */
int get_integer(CryptoPP::Integer *i, std::vector<unsigned char> &data,
                int idx) {
  std::string i_str;
  int n = get_string(&i_str, data, idx);
  *i = CryptoPP::Integer(i_str.c_str());
  return n;
}

// ================================================
// WRAPPERS
// ================================================

/**
 * serialize HMACTagged_Wrapper.
 */
void HMACTagged_Wrapper::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::HMACTagged_Wrapper);

  // Add fields.
  put_string(chvec2str(this->payload), data);

  std::string iv = byteblock_to_string(this->iv);
  put_string(iv, data);

  put_string(this->mac, data);
}

/**
 * deserialize HMACTagged_Wrapper.
 */
int HMACTagged_Wrapper::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::HMACTagged_Wrapper);

  // Get fields.
  std::string payload_string;
  int n = 1;
  n += get_string(&payload_string, data, n);
  this->payload = str2chvec(payload_string);

  std::string iv;
  n += get_string(&iv, data, n);
  this->iv = string_to_byteblock(iv);

  n += get_string(&this->mac, data, n);
  return n;
}

// ================================================
// KEY EXCHANGE
// ================================================

/**
 * serialize DHPublicValue_Message.
 */
void DHPublicValue_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::DHPublicValue_Message);

  // Add fields.
  std::string public_string = byteblock_to_string(this->public_value);
  put_string(public_string, data);
}

/**
 * deserialize DHPublicValue_Message.
 */
int DHPublicValue_Message::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::DHPublicValue_Message);

  // Get fields.
  std::string public_string;
  int n = 1;
  n += get_string(&public_string, data, n);
  this->public_value = string_to_byteblock(public_string);
  return n;
}

// ================================================
// OBLIVIOUS TRANSFER
// ================================================

void SenderToReceiver_OTPublicValue_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::SenderToReceiver_OTPublicValue_Message);

  // Add fields.
  std::string public_integer = byteblock_to_string(this->public_value);
  put_string(public_integer, data);
}

int SenderToReceiver_OTPublicValue_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::SenderToReceiver_OTPublicValue_Message);

  // Get fields.
  std::string public_integer;
  int n = 1;
  n += get_string(&public_integer, data, n);
  this->public_value = string_to_byteblock(public_integer);
  return n;
}

void ReceiverToSender_OTPublicValue_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::ReceiverToSender_OTPublicValue_Message);

  // Add fields.
  std::string public_integer = byteblock_to_string(this->public_value);
  put_string(public_integer, data);
}

int ReceiverToSender_OTPublicValue_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::ReceiverToSender_OTPublicValue_Message);

  // Get fields.
  std::string public_integer;
  int n = 1;
  n += get_string(&public_integer, data, n);
  this->public_value = string_to_byteblock(public_integer);
  return n;
}

void SenderToReceiver_OTEncryptedValues_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::SenderToReceiver_OTEncryptedValues_Message);

  // Add fields.
  put_string(this->e0, data);
  put_string(this->e1, data);

  std::string iv0 = byteblock_to_string(this->iv0);
  put_string(iv0, data);
  std::string iv1 = byteblock_to_string(this->iv1);
  put_string(iv1, data);
}

int SenderToReceiver_OTEncryptedValues_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::SenderToReceiver_OTEncryptedValues_Message);

  // Get fields.
  int n = 1;
  n += get_string(&this->e0, data, n);
  n += get_string(&this->e1, data, n);

  std::string iv0;
  n += get_string(&iv0, data, n);
  this->iv0 = string_to_byteblock(iv0);

  std::string iv1;
  n += get_string(&iv1, data, n);
  this->iv1 = string_to_byteblock(iv1);
  return n;
}

// ================================================
// GARBLED CIRCUITS
// ================================================

void GarblerToEvaluator_GarbledTables_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::GarblerToEvaluator_GarbledTables_Message);

  // Put length of garbled tables.
  int idx = data.size();
  data.resize(idx + sizeof(size_t));
  size_t num_tables = this->garbled_tables.size();
  std::memcpy(&data[idx], &num_tables, sizeof(size_t));

  // Put each table.
  for (int i = 0; i < num_tables; i++) {
    // Put num entries.
    CryptoPP::Integer num_entries = this->garbled_tables[i].entries.size();
    put_integer(num_entries, data);
    for (int j = 0; j < num_entries; j++) {
      std::string entry =
          byteblock_to_string(this->garbled_tables[i].entries[j]);
      put_string(entry, data);
    }
  }
}

int GarblerToEvaluator_GarbledTables_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::GarblerToEvaluator_GarbledTables_Message);

  // Get length
  size_t num_tables;
  std::memcpy(&num_tables, &data[1], sizeof(size_t));

  // Get fields.
  int n = 1 + sizeof(size_t);
  for (int i = 0; i < num_tables; i++) {
    GarbledGate gate;
    CryptoPP::Integer num_entries;
    n += get_integer(&num_entries, data, n);
    for (int j = 0; j < num_entries; j++) {
      std::string entry;
      n += get_string(&entry, data, n);
      gate.entries.push_back(string_to_byteblock(entry));
    }
    this->garbled_tables.push_back(gate);
  }
  return n;
}

void GarblerToEvaluator_GarblerInputs_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::GarblerToEvaluator_GarblerInputs_Message);

  // Put length of garbled inputs.
  int idx = data.size();
  data.resize(idx + sizeof(size_t));
  size_t num_inputs = this->garbler_inputs.size();
  std::memcpy(&data[idx], &num_inputs, sizeof(size_t));

  // Put each table.
  for (int i = 0; i < num_inputs; i++) {
    std::string entry = byteblock_to_string(this->garbler_inputs[i].value);
    put_string(entry, data);
  }
}

int GarblerToEvaluator_GarblerInputs_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::GarblerToEvaluator_GarblerInputs_Message);

  // Get length
  size_t num_inputs;
  std::memcpy(&num_inputs, &data[1], sizeof(size_t));

  // Get fields.
  int n = 1 + sizeof(size_t);
  this->garbler_inputs.resize(num_inputs);
  for (int i = 0; i < num_inputs; i++) {
    std::string entry;
    n += get_string(&entry, data, n);
    this->garbler_inputs[i].value = string_to_byteblock(entry);
  }
  return n;
}

void EvaluatorToGarbler_FinalLabels_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::EvaluatorToGarbler_FinalLabels_Message);

  // Put length of garbled inputs.
  int idx = data.size();
  data.resize(idx + sizeof(size_t));
  size_t num_labels = this->final_labels.size();
  std::memcpy(&data[idx], &num_labels, sizeof(size_t));

  // Put each table.
  for (int i = 0; i < num_labels; i++) {
    std::string entry = byteblock_to_string(this->final_labels[i].value);
    put_string(entry, data);
  }
}

int EvaluatorToGarbler_FinalLabels_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::EvaluatorToGarbler_FinalLabels_Message);

  // Get length
  size_t num_labels;
  std::memcpy(&num_labels, &data[1], sizeof(size_t));

  // Get fields.
  int n = 1 + sizeof(size_t);
  this->final_labels.resize(num_labels);
  for (int i = 0; i < num_labels; i++) {
    std::string entry;
    n += get_string(&entry, data, n);
    this->final_labels[i].value = string_to_byteblock(entry);
  }
  return n;
}

void GarblerToEvaluator_FinalOutput_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::GarblerToEvaluator_FinalOutput_Message);

  // Add fields.
  put_string(this->final_output, data);
}

int GarblerToEvaluator_FinalOutput_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::GarblerToEvaluator_FinalOutput_Message);

  // Get fields.
  int n = 1;
  n += get_string(&this->final_output, data, n);
  return n;
}
