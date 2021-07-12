// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Security.Cryptography;

namespace JsonWebToken.Cryptography
{
    internal static class RsaHelper
    {
        public static RSASignaturePadding GetSignaturePadding(AlgorithmId algorithm)
        {
            RSASignaturePadding? padding;
            if (algorithm <= AlgorithmId.RS256 && algorithm >= AlgorithmId.RS512)
            {
                padding = RSASignaturePadding.Pkcs1;
            }
            else if (algorithm <= AlgorithmId.PS256 && algorithm >= AlgorithmId.PS512)
            {
                padding = RSASignaturePadding.Pss;
            }
            else
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(algorithm);
                padding = RSASignaturePadding.Pkcs1;
            }

            return padding;
        }

        public static RSAEncryptionPadding GetEncryptionPadding(AlgorithmId algorithm)
        {
            return algorithm switch
            {
                AlgorithmId.RsaOaep => RSAEncryptionPadding.OaepSHA1,
                AlgorithmId.Rsa1_5 => RSAEncryptionPadding.Pkcs1,
                AlgorithmId.RsaOaep256 => RSAEncryptionPadding.OaepSHA256,
                AlgorithmId.RsaOaep384 => RSAEncryptionPadding.OaepSHA384,
                AlgorithmId.RsaOaep512 => RSAEncryptionPadding.OaepSHA512,
                _ => throw ThrowHelper.CreateNotSupportedException_AlgorithmForKeyWrap(algorithm)
            };
        }
    }
}