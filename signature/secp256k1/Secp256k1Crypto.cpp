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
 * @brief implementation for secp256k1 signature algorithm
 * @file Secp256k1Signature.cpp
 * @date 2021.03.05
 * @author yujiechen
 */

#include "Secp256k1Crypto.h"
#include "Exceptions.h"
#include "Secp256k1KeyPair.h"
#include <WeDPRCrypto.h>

using namespace bcos;
using namespace bcos::crypto;
Public bcos::crypto::secp256k1Recover(const h256& _hash, std::shared_ptr<bytes> _signatureData)
{
    auto publicKey = wedpr_secp256k1_recover_binary_public_key((const char*)_hash.data(),
        h256::size, (const char*)_signatureData->data(), _signatureData->size());
    if (!publicKey.public_key)
    {
        BOOST_THROW_EXCEPTION(InvalidSignature() << errinfo_comment(
                                  "invalid signature: recover public key failed, msgHash : " +
                                  _hash.hex() + ", signData:" + *toHexString(*_signatureData)));
    }
    // remove the 04 prefix
    auto pubKey = Public(
        bytesConstRef(reinterpret_cast<const byte*>(publicKey.public_key + 1), Public::size));
    dealloc_public_key_data(publicKey);
    return pubKey;
}

std::pair<bool, bytes> bcos::crypto::secp256k1Recover(std::shared_ptr<bytes> _in)
{
    struct
    {
        h256 hash;
        h256 v;
        h256 r;
        h256 s;
    } in;
    memcpy(&in, _in->data(), std::min(_in->size(), sizeof(*_in)));
    u256 v = (u256)in.v;
    if (v >= 27 && v <= 28)
    {
        auto signatureData =
            std::make_shared<Secp256k1SignatureData>(in.r, in.s, (byte)((int)v - 27));
        try
        {
            auto encodedBytes = std::make_shared<bytes>();
            signatureData->encode(encodedBytes);
            auto publicKey = secp256k1Recover(in.hash, encodedBytes);
            auto address = secp256k1ToAddress(publicKey);
            memset(address.data(), 0, 12);
            return {true, address.asBytes()};
        }
        catch (const std::exception& e)
        {
        }
    }
    return {false, {}};
}