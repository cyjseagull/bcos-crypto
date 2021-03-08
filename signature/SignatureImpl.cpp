/**
 *  Copyright (C) 2021 FISCO BCOS.
 *  SPDX-License-Identifier: Apache-2.0
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 * @brief call wedpr-crypto to implement secp256k1/sm2 signature
 * @file SignatureImpl.cpp
 * @date 2021.03.05
 * @author yujiechen
 */
#include "SignatureImpl.h"
#include "Exceptions.h"
#include "secp256k1/Secp256k1KeyPair.h"
#include "sm2/SM2KeyPair.h"
#include <WeDPRCrypto.h>
#include <bcos-framework/libutilities/Log.h>

using namespace bcos;
using namespace bcos::crypto;
Public bcos::crypto::priToPub(SignatureOption _signatureOption, Secret const& _secret)
{
    PublicKey publicKey;
    switch (_signatureOption)
    {
    case SignatureOption::SECP256K1:
        publicKey = wedpr_secp256k1_derive_binary_public_key((char*)_secret.data(), Secret::size);
        break;
    case SignatureOption::SM2:
        publicKey = wedpr_sm2_derive_binary_public_key((const char*)_secret.data(), Secret::size);
        break;
    default:
        BOOST_THROW_EXCEPTION(
            UnsupportedSignatureAlgorithm() << errinfo_comment(
                "unsupported signature algorithm type, only support secp256k1/sm2 now"));
    }
    if (!publicKey.public_key)
    {
        LOG(WARNING) << LOG_DESC("Secp256k1KeyPair::priToPub exception");
        BOOST_THROW_EXCEPTION(PriToPublicKeyException() << errinfo_comment(
                                  "calculate publicKey through privateKey exception"));
    }
    Public pubKey;
    // the public key with 04 prefix, remove the prefix
    if (publicKey.public_key_len == Public::size)
    {
        pubKey = Public(reinterpret_cast<const byte*>(publicKey.public_key),
            Public::ConstructorType::FromPointer);
    }
    else if (publicKey.public_key_len == Public::size + 1)
    {
        pubKey = Public(reinterpret_cast<const byte*>(publicKey.public_key + 1),
            Public::ConstructorType::FromPointer);
    }
    else
    {
        BOOST_THROW_EXCEPTION(
            InvalidPublicKey() << errinfo_comment(
                "calculate publicKey through privateKey exception for invalid publicKey"));
    }
    dealloc_public_key_data(publicKey);
    return pubKey;
}

std::shared_ptr<bytes> bcos::crypto::sign(
    SignatureOption _signatureOption, KeyPair const& _keyPair, const h256& _hash)
{
    SignatureResult signatureResult;
    switch (_signatureOption)
    {
    case SignatureOption::SECP256K1:
        signatureResult = wedpr_secp256k1_sign_binary((const char*)_keyPair.secretKey().data(),
            Secret::size, (const char*)_hash.data(), h256::size);
        break;
    case SignatureOption::SM2:
        signatureResult = wedpr_sm2_sign_binary_fast((const char*)_keyPair.secretKey().data(),
            Secret::size, (const char*)_keyPair.publicKey().data(), Public::size,
            (const char*)_hash.data(), h256::size);
        break;
    default:
        BOOST_THROW_EXCEPTION(
            UnsupportedSignatureAlgorithm() << errinfo_comment(
                "unsupported signature algorithm type, only support secp256k1/sm2 now"));
    }
    if (!signatureResult.signature_data)
    {
        LOG(WARNING) << LOG_DESC("Secp256k1Signature sign failed") << LOG_KV("hash", _hash.hex());
        BOOST_THROW_EXCEPTION(
            SignatureException() << errinfo_comment("sign data failed, raw data: " + _hash.hex()));
    }
    auto signData = std::make_shared<bytes>((byte*)signatureResult.signature_data,
        (byte*)(signatureResult.signature_data + signatureResult.signature_len));
    dealloc_signature_data(signatureResult);
    return signData;
}

bool bcos::crypto::verify(SignatureOption _signatureOption, Public const& _pubKey,
    const h256& _hash, bytesConstRef _signatureData)
{
    int verifyResult = 0;
    switch (_signatureOption)
    {
    case SignatureOption::SECP256K1:
        verifyResult = wedpr_secp256k1_verify_binary((const char*)_pubKey.data(), Public::size,
            (const char*)_hash.data(), h256::size, (const char*)_signatureData.data(),
            _signatureData.size());
        break;
    case SignatureOption::SM2:
        verifyResult = wedpr_sm2_verify_binary((const char*)_pubKey.data(), Public::size,
            (const char*)_hash.data(), h256::size, (const char*)_signatureData.data(),
            _signatureData.size());
        break;
    default:
        BOOST_THROW_EXCEPTION(
            UnsupportedSignatureAlgorithm() << errinfo_comment(
                "unsupported signature algorithm type, only support secp256k1/sm2 now"));
    }
    if (verifyResult == 0)
    {
        return true;
    }
    return false;
}

std::shared_ptr<KeyPair> bcos::crypto::generateKeyPair(SignatureOption _signatureOption)
{
    KeyPairData keyPairData;
    std::shared_ptr<KeyPair> keyPair;
    switch (_signatureOption)
    {
    case SignatureOption::SECP256K1:
        keyPairData = wedpr_secp256k1_gen_binary_key_pair();
        keyPair = std::make_shared<Secp256k1KeyPair>();
        break;
    case SignatureOption::SM2:
        keyPairData = wedpr_sm2_gen_binary_key_pair();
        keyPair = std::make_shared<SM2KeyPair>();
        break;
    default:
        BOOST_THROW_EXCEPTION(
            UnsupportedSignatureAlgorithm() << errinfo_comment(
                "unsupported signature algorithm type, only support secp256k1/sm2 now"));
    }
    if (!keyPairData.public_key)
    {
        BOOST_THROW_EXCEPTION(SignatureException() << errinfo_comment("GenerateKeyPairException"));
    }
    // the public key with 04 prefix, remove the 04 prefix
    keyPair->setPublicKey(Public(
        bytesConstRef(reinterpret_cast<const byte*>(keyPairData.public_key + 1), Public::size)));
    keyPair->setSecretKey(Secret(
        bytesConstRef(reinterpret_cast<const byte*>(keyPairData.private_key), Secret::size)));
    dealloc_key_pair(keyPairData);
    return keyPair;
}