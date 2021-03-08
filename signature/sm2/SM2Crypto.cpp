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
 * @brief implementation for sm2 signature
 * @file SM2Crypto.cpp
 * @date 2021.03.10
 * @author yujiechen
 */
#include "SM2Crypto.h"
#include <bcos-crypto/hash/SM3.h>
#include <bcos-crypto/signature/Exceptions.h>
#include <bcos-crypto/signature/SignatureImpl.h>

using namespace bcos;
using namespace bcos::crypto;

std::shared_ptr<bytes> bcos::crypto::sm2Sign(KeyPair const& _keyPair, const h256& _hash)
{
    auto signatureData = sign(SignatureOption::SM2, _keyPair, _hash);
    // append the public key
    signatureData->insert(
        signatureData->end(), _keyPair.publicKey().begin(), _keyPair.publicKey().end());
    return signatureData;
}

std::shared_ptr<KeyPair> bcos::crypto::sm2GenerateKeyPair()
{
    return generateKeyPair(SignatureOption::SM2);
}

bool bcos::crypto::sm2Verify(
    Public const& _pubKey, const h256& _hash, std::shared_ptr<bytes> _signatureData)
{
    auto signatureWithoutPub = bytesRef(_signatureData->data(), 64);
    return verify(SignatureOption::SM2, _pubKey, _hash, signatureWithoutPub);
}

Public bcos::crypto::sm2Recover(const h256& _hash, std::shared_ptr<bytes> _signData)
{
    auto signatureStruct = std::make_shared<SM2SignatureData>(*_signData);
    if (sm2Verify(signatureStruct->pub(), _hash, _signData))
    {
        return signatureStruct->pub();
    }
    BOOST_THROW_EXCEPTION(InvalidSignature() << errinfo_comment(
                              "invalid signature: sm2 recover public key failed, msgHash : " +
                              _hash.hex() + ", signature:" + *toHexString(*_signData)));
}

std::pair<bool, bytes> bcos::crypto::sm2Recover(std::shared_ptr<bytes> _in)
{
    struct
    {
        h256 hash;
        h512 pub;
        h256 r;
        h256 s;
    } in;
    memcpy(&in, _in->data(), std::min(_in->size(), sizeof(*_in)));
    // verify the signature
    auto signatureData = std::make_shared<SM2SignatureData>(in.r, in.s, in.pub);
    try
    {
        std::shared_ptr<bytes> encodedData = std::make_shared<bytes>();
        signatureData->encode(encodedData);
        if (sm2Verify(signatureData->pub(), in.hash, encodedData))
        {
            auto address = sm3Hash(signatureData->pub().ref());
            memset(address.data(), 0, 12);
            return {true, address.asBytes()};
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
    return {false, {}};
}
