#include <iostream>
#include <stdexcept>
#include <string>

#include "crypto++/base64.h"
#include "crypto++/dsa.h"
#include "crypto++/osrng.h"
#include "crypto++/rsa.h"
#include <crypto++/cryptlib.h>
#include <crypto++/elgamal.h>
#include <crypto++/files.h>
#include <crypto++/hkdf.h>
#include <crypto++/nbtheory.h>
#include <crypto++/queue.h>
#include <crypto++/sha.h>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/messages.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/ot_driver.hpp"

/*
 * Constructor
 */
OTDriver::OTDriver(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {
  this->network_driver = network_driver;
  this->crypto_driver = crypto_driver;
  this->AES_key = keys.first;
  this->HMAC_key = keys.second;
  this->cli_driver = std::make_shared<CLIDriver>();
}

/*
 * Send either m0 or m1 using OT. This function should:
 * 1) Sample a public DH value and send it to the receiver
 * 2) Receive the receiver's public value
 * 3) Encrypt m0 and m1 using different keys
 * 4) Send the encrypted values
 * You may find `byteblock_to_integer` and `integer_to_byteblock` useful
 * Disconnect and throw errors only for invalid MACs
 */
void OTDriver::OT_send(std::string m0, std::string m1) {
  // TODO: implement me!
  std::pair<std::vector<unsigned char>, bool> intermediate;

  //get DH keys
  std::tuple<CryptoPP::DH, CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> obj_priv_pub_key = this->crypto_driver->DH_initialize();

  //send my public value
  SenderToReceiver_OTPublicValue_Message public_msg;
  public_msg.public_value = std::get<2>(obj_priv_pub_key);
  this->network_driver->send(this->crypto_driver->encrypt_and_tag(this->AES_key, this->HMAC_key, &public_msg));

  //get the other persons public value
  intermediate = this->crypto_driver->decrypt_and_verify(this->AES_key, this->HMAC_key, this->network_driver->read());
  if(std::get<1>(intermediate) == false) {
    throw std::runtime_error("OTDriver::OT_send - failed to varify HMAC for other persons public value");
  }
  ReceiverToSender_OTPublicValue_Message other_public_msg;
  other_public_msg.deserialize(std::get<0>(intermediate));

  //generate key 0 and key 1
  CryptoPP::SecByteBlock k_0_inter = this->crypto_driver->DH_generate_shared_key(std::get<0>(obj_priv_pub_key), std::get<1>(obj_priv_pub_key), other_public_msg.public_value);
  CryptoPP::SecByteBlock temp = integer_to_byteblock(
    (byteblock_to_integer(other_public_msg.public_value) * CryptoPP::EuclideanMultiplicativeInverse(byteblock_to_integer(std::get<2>(obj_priv_pub_key)), DL_P)) % DL_P
  );
  CryptoPP::SecByteBlock k_1_inter = this->crypto_driver->DH_generate_shared_key(std::get<0>(obj_priv_pub_key), std::get<1>(obj_priv_pub_key), temp);

  CryptoPP::SecByteBlock k_0 = this->crypto_driver->AES_generate_key(k_0_inter);
  CryptoPP::SecByteBlock k_1 = this->crypto_driver->AES_generate_key(k_1_inter);

  //encrypt the messages
  SenderToReceiver_OTEncryptedValues_Message enc_msgs_to_send;
  std::pair<std::string, CryptoPP::SecByteBlock> m0_enc = this->crypto_driver->AES_encrypt(k_0, m0);
  std::pair<std::string, CryptoPP::SecByteBlock> m1_enc = this->crypto_driver->AES_encrypt(k_1, m1);
  enc_msgs_to_send.e0 = std::get<0>(m0_enc);
  enc_msgs_to_send.iv0 = std::get<1>(m0_enc);
  enc_msgs_to_send.e1 = std::get<0>(m1_enc);
  enc_msgs_to_send.iv1 = std::get<1>(m1_enc);

  //send the message
  this->network_driver->send(this->crypto_driver->encrypt_and_tag(this->AES_key, this->HMAC_key, &enc_msgs_to_send));
}

/*
 * Receive m_c using OT. This function should:
 * 1) Read the sender's public value
 * 2) Respond with our public value that depends on our choice bit
 * 3) Generate the appropriate key and decrypt the appropriate ciphertext
 * You may find `byteblock_to_integer` and `integer_to_byteblock` useful
 * Disconnect and throw errors only for invalid MACs
 */
std::string OTDriver::OT_recv(int choice_bit) {
  // TODO: implement me!
  std::pair<std::vector<unsigned char>, bool> intermediate;

  //generate DH keys
  std::tuple<CryptoPP::DH, CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> obj_priv_pub_key = this->crypto_driver->DH_initialize();

  //get the other perons public DH key
  intermediate = this->crypto_driver->decrypt_and_verify(this->AES_key, this->HMAC_key, this->network_driver->read());
  if(std::get<1>(intermediate) == false) {
    throw std::runtime_error("OTDriver::OT_recv - failed to varify HMAC for other persons public value");
  }
  SenderToReceiver_OTPublicValue_Message other_public_key;
  other_public_key.deserialize(std::get<0>(intermediate));

  //generate message based on choice bit
  ReceiverToSender_OTPublicValue_Message choice;
  if (choice_bit == 0) {
    choice.public_value = std::get<2>(obj_priv_pub_key);
  } else {
    choice.public_value = integer_to_byteblock((byteblock_to_integer(other_public_key.public_value) * byteblock_to_integer(std::get<2>(obj_priv_pub_key))) % DL_P);
  }

  //send message to other person
  this->network_driver->send(this->crypto_driver->encrypt_and_tag(this->AES_key, this->HMAC_key, &choice));

  //get the encrypted messages
  intermediate = this->crypto_driver->decrypt_and_verify(this->AES_key, this->HMAC_key, this->network_driver->read());
  if(std::get<1>(intermediate) == false) {
    throw std::runtime_error("OTDriver::OT_recv - failed to varify HMAC for other persons encrypted ciphers");
  }
  SenderToReceiver_OTEncryptedValues_Message enc_msgs;
  enc_msgs.deserialize(std::get<0>(intermediate));

  //generate the proper key for decryption
  CryptoPP::SecByteBlock k_c_inter = this->crypto_driver->DH_generate_shared_key(std::get<0>(obj_priv_pub_key), std::get<1>(obj_priv_pub_key), other_public_key.public_value); 
  CryptoPP::SecByteBlock k_c = this->crypto_driver->AES_generate_key(k_c_inter);

  //decrypt proper message
  std::string msg;
  if (choice_bit == 0) {
    msg = this->crypto_driver->AES_decrypt(k_c, enc_msgs.iv0, enc_msgs.e0);
  } else {
    msg = this->crypto_driver->AES_decrypt(k_c, enc_msgs.iv1, enc_msgs.e1);
  }

  return msg;
}