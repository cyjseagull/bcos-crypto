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
 * @brief implementation for secp256k1 KeyPair
 * @file Secp256k1KeyPair.cpp
 * @date 2021.03.05
 * @author yujiechen
 */
#include "Secp256k1KeyPair.h"
#include "hash/Keccak256.h"
#include <bcos-crypto/signature/SignatureImpl.h>

bcos::crypto::Public bcos::crypto::secp256k1PriToPub(bcos::crypto::Secret const& _secret)
{
    return bcos::crypto::priToPub(bcos::crypto::SignatureOption::SECP256K1, _secret);
}

bcos::Address bcos::crypto::secp256k1ToAddress(bcos::crypto::Public const& _pubKey)
{
    return right160(keccak256Hash(_pubKey.ref()));
}

std::shared_ptr<bcos::crypto::KeyPair> bcos::crypto::generateSecp256k1KeyPair()
{
    return bcos::crypto::generateKeyPair(SignatureOption::SECP256K1);
}