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
 * @file Secp256k1Crypto.h
 * @date 2021.03.05
 * @author yujiechen
 */

#pragma once
#include <bcos-crypto/signature/SignatureImpl.h>
#include <bcos-framework/interfaces/crypto/Signature.h>

namespace bcos
{
namespace crypto
{
std::shared_ptr<bytes> inline secp256k1Sign(KeyPair const& _keyPair, const h256& _hash)
{
    return sign(SignatureOption::SECP256K1, _keyPair, _hash);
}

bool inline secp256k1Verify(
    Public const& _pubKey, const h256& _hash, std::shared_ptr<bytes> _signatureData)
{
    return verify(SignatureOption::SECP256K1, _pubKey, _hash, ref(*_signatureData));
}

std::shared_ptr<KeyPair> inline secp256k1GenerateKeyPair()
{
    return generateKeyPair(SignatureOption::SECP256K1);
}

Public secp256k1Recover(const h256& _hash, std::shared_ptr<bytes> _signatureData);
std::pair<bool, bytes> inline secp256k1Recover(std::shared_ptr<bytes> _in);

class Secp256k1SignatureData : public SignatureData
{
public:
    using Ptr = std::shared_ptr<Secp256k1SignatureData>;
    explicit Secp256k1SignatureData(bytes const& _data)
    {
        m_signatureLen = c_secp256k1SignatureLen;
        decode(_data);
    }
    Secp256k1SignatureData(h256 const& _r, h256 const& _s, byte const& _v)
      : SignatureData(_r, _s), m_v(_v)
    {
        m_signatureLen = c_secp256k1SignatureLen;
    }
    ~Secp256k1SignatureData() override {}

    byte const& v() { return m_v; }

    void encode(bytesPointer _signatureData) const override
    {
        encodeCommonFields(_signatureData);
        (*_signatureData)[m_signatureLen - 1] = m_v;
    }
    void decode(bytes const& _signatureData) override
    {
        decodeCommonFields(_signatureData);
        m_v = (byte)(_signatureData[m_signatureLen - 1]);
    }

public:
    const size_t c_secp256k1SignatureLen = 65;

private:
    byte m_v;
};

class Secp256k1Crypto : public SignatureCrypto
{
public:
    using Ptr = std::shared_ptr<Secp256k1Crypto>;
    Secp256k1Crypto() = default;
    ~Secp256k1Crypto() override {}
    std::shared_ptr<bytes> sign(KeyPair const& _keyPair, const h256& _hash) override
    {
        return secp256k1Sign(_keyPair, _hash);
    }
    bool verify(
        Public const& _pubKey, const h256& _hash, std::shared_ptr<bytes> _signatureData) override
    {
        return secp256k1Verify(_pubKey, _hash, _signatureData);
    }

    Public recover(const h256& _hash, std::shared_ptr<bytes> _signatureData) override
    {
        return secp256k1Recover(_hash, _signatureData);
    }
    std::shared_ptr<KeyPair> generateKeyPair() override { return secp256k1GenerateKeyPair(); }
};
}  // namespace crypto
}  // namespace bcos
