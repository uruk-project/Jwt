// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;
#if SUPPORT_SIMD
#endif

namespace JsonWebToken
{
    internal sealed class DefaultAesBlockDecryptor : AesBlockDecryptor
    {
        private readonly Aes _aes;
        private readonly ICryptoTransform _decryptor;

        public DefaultAesBlockDecryptor(ReadOnlySpan<byte> key)
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
            _decryptor = _aes.CreateDecryptor();
        }

        public override void DecryptBlock(ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
        {
            var block = _decryptor.TransformFinalBlock(ciphertext.ToArray(), 0, 16);
            block.CopyTo(plaintext);

        }

        public override void Dispose()
        {
            _aes.Dispose();
            _decryptor.Dispose();
        }
    }
}
