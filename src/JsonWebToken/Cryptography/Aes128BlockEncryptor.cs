// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if SUPPORT_SIMD
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace JsonWebToken.Internal
{
    internal sealed class Aes128BlockEncryptor : AesBlockEncryptor
    {
        private readonly Aes128EncryptionKeys _keys;

        public Aes128BlockEncryptor(ReadOnlySpan<byte> key)
        {
            _keys = new Aes128EncryptionKeys(key);
        }

        /// <inheritsdoc />
        public override void Dispose()
        {
            // Clear the keys
            _keys.Clear();
        }

        public override void EncryptBlock(ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
        {
            var block = Unsafe.ReadUnaligned<Vector128<byte>>(ref MemoryMarshal.GetReference(plaintext));

            block = Sse2.Xor(block, _keys.Key0);
            block = Aes.Encrypt(block, _keys.Key1);
            block = Aes.Encrypt(block, _keys.Key2);
            block = Aes.Encrypt(block, _keys.Key3);
            block = Aes.Encrypt(block, _keys.Key4);
            block = Aes.Encrypt(block, _keys.Key5);
            block = Aes.Encrypt(block, _keys.Key6);
            block = Aes.Encrypt(block, _keys.Key7);
            block = Aes.Encrypt(block, _keys.Key8);
            block = Aes.Encrypt(block, _keys.Key9);
            block = Aes.EncryptLast(block, _keys.Key10);
            Unsafe.WriteUnaligned(ref MemoryMarshal.GetReference(ciphertext), block);
        }
    }
}
#endif