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
    internal sealed class Aes256BlockDecryptor : AesBlockDecryptor
    {
        private readonly Aes256DecryptionKeys _keys;

        public Aes256BlockDecryptor(ReadOnlySpan<byte> key)
        {
            _keys = new Aes256DecryptionKeys(key);
        }

        /// <inheritsdoc />
        public override void Dispose()
        {
            // Clear the keys
            _keys.Clear();
        }

        public override void DecryptBlock(ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
        {
            var block = Unsafe.ReadUnaligned<Vector128<byte>>(ref MemoryMarshal.GetReference(ciphertext));
            block = Sse2.Xor(block, _keys.Key0);
            block = Aes.Decrypt(block, _keys.Key1);
            block = Aes.Decrypt(block, _keys.Key2);
            block = Aes.Decrypt(block, _keys.Key3);
            block = Aes.Decrypt(block, _keys.Key4);
            block = Aes.Decrypt(block, _keys.Key5);
            block = Aes.Decrypt(block, _keys.Key6);
            block = Aes.Decrypt(block, _keys.Key7);
            block = Aes.Decrypt(block, _keys.Key8);
            block = Aes.Decrypt(block, _keys.Key9);
            block = Aes.Decrypt(block, _keys.Key10);
            block = Aes.Decrypt(block, _keys.Key11);
            block = Aes.Decrypt(block, _keys.Key12);
            block = Aes.Decrypt(block, _keys.Key13);
            block = Aes.DecryptLast(block, _keys.Key14);
            Unsafe.WriteUnaligned(ref MemoryMarshal.GetReference(plaintext), block);
        }
    }
}
#endif