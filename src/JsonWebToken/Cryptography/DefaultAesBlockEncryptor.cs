// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;

namespace JsonWebToken.Cryptography
{
    internal sealed class DefaultAesBlockEncryptor : AesBlockEncryptor
    {
        private readonly Aes _aes;
        private readonly ICryptoTransform _encryptor;

        public DefaultAesBlockEncryptor(ReadOnlySpan<byte> key)
        {
            byte[] keyBytes = key.ToArray();
            _aes = Aes.Create();
            _aes.Mode = CipherMode.ECB; // lgtm [cs/ecb-encryption]
            _aes.Padding = PaddingMode.None;
            _aes.KeySize = keyBytes.Length << 3;
            _aes.Key = keyBytes;

            // Set the AES IV to Zeroes
            var iv = new byte[_aes.BlockSize >> 3];
            Array.Clear(iv, 0, iv.Length);
            _aes.IV = iv;
            _encryptor = _aes.CreateEncryptor();
        }

        public override void EncryptBlock(ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
        {
            var block = _encryptor.TransformFinalBlock(plaintext.ToArray(), 0, 16);
            block.CopyTo(ciphertext);
        }

        public override void Dispose()
        {
            _aes.Dispose();
            _encryptor.Dispose();
        }
    }
}
