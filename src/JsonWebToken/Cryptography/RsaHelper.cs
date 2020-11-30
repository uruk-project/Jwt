// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Security.Cryptography;

namespace JsonWebToken.Cryptography
{
    internal static class RsaHelper
    {
        public static RSASignaturePadding GetPadding(SignatureAlgorithm algorithm)
        {
            return algorithm.Id switch
            {
                AlgorithmId.RsaSha256 => RSASignaturePadding.Pkcs1,
                AlgorithmId.RsaSha384 => RSASignaturePadding.Pkcs1,
                AlgorithmId.RsaSha512 => RSASignaturePadding.Pkcs1,
                AlgorithmId.RsaSsaPssSha256 => RSASignaturePadding.Pss,
                AlgorithmId.RsaSsaPssSha384 => RSASignaturePadding.Pss,
                AlgorithmId.RsaSsaPssSha512 => RSASignaturePadding.Pss,
                _ => throw ThrowHelper.CreateNotSupportedException_Algorithm(algorithm)
            };
        }
    }
}