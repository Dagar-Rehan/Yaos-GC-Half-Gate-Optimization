#pragma once

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <boost/chrono.hpp>
#include <boost/thread.hpp>
#include <crypto++/cryptlib.h>
#include <crypto++/dsa.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>

#include "../include-shared/circuit.hpp"

// ================================================
// MESSAGE TYPES
// ================================================

namespace MessageType {
enum T {
  HMACTagged_Wrapper = 1,
  DHPublicValue_Message = 2,
  SenderToReceiver_OTPublicValue_Message = 3,
  ReceiverToSender_OTPublicValue_Message = 4,
  SenderToReceiver_OTEncryptedValues_Message = 5,
  GarblerToEvaluator_GarbledTables_Message = 6,
  GarblerToEvaluator_GarblerInputs_Message = 7,
  EvaluatorToGarbler_FinalLabels_Message = 8,
  GarblerToEvaluator_FinalOutput_Message = 9,
};
};
MessageType::T get_message_type(std::vector<unsigned char> &data);

// ================================================
// SERIALIZABLE
// ================================================

struct Serializable {
  virtual void serialize(std::vector<unsigned char> &data) = 0;
  virtual int deserialize(std::vector<unsigned char> &data) = 0;
};

// serializers.
int put_bool(bool b, std::vector<unsigned char> &data);
int put_string(std::string s, std::vector<unsigned char> &data);
int put_integer(CryptoPP::Integer i, std::vector<unsigned char> &data);

// deserializers
int get_bool(bool *b, std::vector<unsigned char> &data, int idx);
int get_string(std::string *s, std::vector<unsigned char> &data, int idx);
int get_integer(CryptoPP::Integer *i, std::vector<unsigned char> &data,
                int idx);

// ================================================
// WRAPPERS
// ================================================

struct HMACTagged_Wrapper : public Serializable {
  std::vector<unsigned char> payload;
  CryptoPP::SecByteBlock iv;
  std::string mac;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// ================================================
// KEY EXCHANGE
// ================================================

struct DHPublicValue_Message : public Serializable {
  CryptoPP::SecByteBlock public_value;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// ================================================
// OBLIVIOUS TRANSFER
// ================================================

struct SenderToReceiver_OTPublicValue_Message : public Serializable {
  CryptoPP::SecByteBlock public_value;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct ReceiverToSender_OTPublicValue_Message : public Serializable {
  CryptoPP::SecByteBlock public_value;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct SenderToReceiver_OTEncryptedValues_Message : public Serializable {
  std::string e0;
  std::string e1;
  // we need to send IVs outputted by AES_encrypt
  CryptoPP::SecByteBlock iv0;
  CryptoPP::SecByteBlock iv1;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// ================================================
// GARBLED CIRCUITS
// ================================================

struct GarblerToEvaluator_GarbledTables_Message : public Serializable {
  std::vector<GarbledGate> garbled_tables;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct GarblerToEvaluator_GarblerInputs_Message : public Serializable {
  std::vector<GarbledWire> garbler_inputs;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct EvaluatorToGarbler_FinalLabels_Message : public Serializable {
  std::vector<GarbledWire> final_labels;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct GarblerToEvaluator_FinalOutput_Message : public Serializable {
  std::string final_output;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};
