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
#include <crypto++/nbtheory.h>
#include <crypto++/queue.h>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/crypto_driver.hpp"

using namespace CryptoPP;

/**
 * @brief Encrypts the given message using AES and tags the ciphertext with an
 * HMAC. Outputs an HMACTagged_Wrapper as bytes.
 */
std::vector<unsigned char>
CryptoDriver::encrypt_and_tag(SecByteBlock AES_key, SecByteBlock HMAC_key,
                              Serializable *message) {
  // Serialize given message.
  std::vector<unsigned char> plaintext;
  message->serialize(plaintext);

  // Encrypt the payload, generate iv to hmac.
  std::pair<std::string, SecByteBlock> encrypted =
      this->AES_encrypt(AES_key, chvec2str(plaintext));
  std::string to_tag = std::string((const char *)encrypted.second.data(),
                                   encrypted.second.size()) +
                       encrypted.first;

  // Generate HMAC on the payload.
  HMACTagged_Wrapper msg;
  msg.payload = str2chvec(encrypted.first);
  msg.iv = encrypted.second;
  msg.mac = this->HMAC_generate(HMAC_key, to_tag);

  // Serialize the HMAC and payload.
  std::vector<unsigned char> payload_data;
  msg.serialize(payload_data);
  return payload_data;
}

/**
 * @brief Verifies that the tagged HMAC is valid on the ciphertext and decrypts
 * the given message using AES. Takes in an HMACTagged_Wrapper as bytes.
 */
std::pair<std::vector<unsigned char>, bool>
CryptoDriver::decrypt_and_verify(SecByteBlock AES_key, SecByteBlock HMAC_key,
                                 std::vector<unsigned char> ciphertext_data) {
  // Deserialize
  HMACTagged_Wrapper ciphertext;
  ciphertext.deserialize(ciphertext_data);

  // Verify HMAC
  std::string to_verify =
      std::string((const char *)ciphertext.iv.data(), ciphertext.iv.size()) +
      chvec2str(ciphertext.payload);
  bool valid = this->HMAC_verify(HMAC_key, to_verify, ciphertext.mac);

  // Decrypt
  std::string plaintext =
      this->AES_decrypt(AES_key, ciphertext.iv, chvec2str(ciphertext.payload));
  std::vector<unsigned char> plaintext_data = str2chvec(plaintext);
  return std::make_pair(plaintext_data, valid);
}

/**
 * @brief Generate DH keypair.
 */
std::tuple<DH, SecByteBlock, SecByteBlock> CryptoDriver::DH_initialize() {
  DH DH_obj(DL_P, DL_Q, DL_G);
  AutoSeededRandomPool prng;
  SecByteBlock DH_private_key(DH_obj.PrivateKeyLength());
  SecByteBlock DH_public_key(DH_obj.PublicKeyLength());
  DH_obj.GenerateKeyPair(prng, DH_private_key, DH_public_key);
  return std::make_tuple(DH_obj, DH_private_key, DH_public_key);
}

/**
 * @brief Generates a shared secret.
 */
SecByteBlock CryptoDriver::DH_generate_shared_key(
    const DH &DH_obj, const SecByteBlock &DH_private_value,
    const SecByteBlock &DH_other_public_value) {
  SecByteBlock DH_shared_key(DH_obj.AgreedValueLength());
  SecByteBlock private_key_real =
      SecByteBlock(NULL, DH_obj.PrivateKeyLength() - DH_private_value.size()) +
      DH_private_value;
  SecByteBlock other_key_real =
      SecByteBlock(NULL,
                   DH_obj.PublicKeyLength() - DH_other_public_value.size()) +
      DH_other_public_value;
  if (!DH_obj.Agree(DH_shared_key, private_key_real, other_key_real)) {
    throw std::runtime_error("Error: failed to reach shared secret.");
  }
  return DH_shared_key;
}

/**
 * @brief Generates AES key using HKDF with a salt.
 */
SecByteBlock CryptoDriver::AES_generate_key(const SecByteBlock &DH_shared_key) {
  std::string aes_salt_str("salt0000");
  SecByteBlock aes_salt((const unsigned char *)(aes_salt_str.data()),
                        aes_salt_str.size());
  // Derive AES key using HKDF
  SecByteBlock AES_shared_key(AES::DEFAULT_KEYLENGTH);
  HKDF<SHA256> hkdf;
  hkdf.DeriveKey(AES_shared_key, AES_shared_key.size(), DH_shared_key,
                 DH_shared_key.size(), aes_salt, aes_salt.size(), NULL, 0);

  return AES_shared_key;
}

/**
 * @brief Encrypts the given plaintext.
 */
std::pair<std::string, SecByteBlock>
CryptoDriver::AES_encrypt(SecByteBlock key, std::string plaintext) {
  try {
    // Create encryptor and set key
    CBC_Mode<AES>::Encryption AES_encryptor = CBC_Mode<AES>::Encryption();

    SecByteBlock iv(AES::BLOCKSIZE);
    AutoSeededRandomPool rng;
    AES_encryptor.GetNextIV(rng, iv.BytePtr());
    AES_encryptor.SetKeyWithIV(key, key.size(), iv);

    // Encrypt using a StreamTransformationFilter
    std::string ciphertext;
    StringSource ss1(plaintext, true,
                     new StreamTransformationFilter(
                         AES_encryptor, new StringSink(ciphertext)));

    return std::make_pair(ciphertext, iv);
  } catch (CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    std::cerr << "This function was likely called with an incorrect shared key."
              << std::endl;
    throw std::runtime_error("CryptoDriver AES encryption failed.");
  }
}

/**
 * @brief Decrypts the given ciphertext.
 */
std::string CryptoDriver::AES_decrypt(SecByteBlock key, SecByteBlock iv,
                                      std::string ciphertext) {
  try {
    CBC_Mode<AES>::Decryption AES_decryptor = CBC_Mode<AES>::Decryption();
    AES_decryptor.SetKeyWithIV(key, key.size(), iv);

    // Decrypt using a StreamTransformationFilter
    std::string recovered;
    StringSource ss1(ciphertext, true,
                     new StreamTransformationFilter(AES_decryptor,
                                                    new StringSink(recovered)));
    return recovered;
  } catch (CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    std::cerr << "This function was likely called with an incorrect shared key."
              << std::endl;
    throw std::runtime_error("CryptoDriver AES decryption failed.");
  }
}

/**
 * @brief Generates an HMAC key using HKDF with a salt.
 */
SecByteBlock
CryptoDriver::HMAC_generate_key(const SecByteBlock &DH_shared_key) {
  std::string hmac_salt_str("salt0001");
  SecByteBlock hmac_salt((const unsigned char *)(hmac_salt_str.data()),
                         hmac_salt_str.size());
  // Derive 256 byte ECB key from DH shared key using KDF
  HKDF<SHA256> hkdf;
  SecByteBlock HMAC_shared_key(SHA256::BLOCKSIZE);
  hkdf.DeriveKey(HMAC_shared_key, HMAC_shared_key.size(), DH_shared_key,
                 DH_shared_key.size(), hmac_salt, hmac_salt.size(), NULL, 0);
  return HMAC_shared_key;
}

/**
 * @brief Given a ciphertext, generates an HMAC
 */
std::string CryptoDriver::HMAC_generate(SecByteBlock key,
                                        std::string ciphertext) {
  try {
    std::string mac;
    HMAC<SHA256> hmac(key, key.size());
    StringSource ss2(ciphertext, true,
                     new HashFilter(hmac, new StringSink(mac)));
    return mac;
  } catch (const CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    throw std::runtime_error("CryptoDriver HMAC generation failed.");
  }
}

/**
 * @brief Given a message and MAC, checks the MAC is valid.
 */
bool CryptoDriver::HMAC_verify(SecByteBlock key, std::string ciphertext,
                               std::string mac) {
  const int flags = HashVerificationFilter::THROW_EXCEPTION |
                    HashVerificationFilter::HASH_AT_END;
  try {
    HMAC<SHA256> hmac(key, key.size());
    StringSource(ciphertext + mac, true,
                 new HashVerificationFilter(hmac, NULL, flags));
    return true;
  } catch (const CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    return false;
  }
}

/**
 * Hash inputs. SHA256(lhs || rhs)
 */
CryptoPP::SecByteBlock CryptoDriver::hash_inputs(CryptoPP::SecByteBlock &lhs,
                                                 CryptoPP::SecByteBlock &rhs) {
  CryptoPP::SHA256 hash;
  CryptoPP::SecByteBlock digest(hash.DigestSize());
  CryptoPP::SecByteBlock appended = lhs + rhs;
  hash.Update(appended.BytePtr(), appended.size());
  hash.Final(digest.BytePtr());
  return digest;
}
