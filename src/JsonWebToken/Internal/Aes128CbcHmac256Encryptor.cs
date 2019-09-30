// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

#if NETCOREAPP3_0
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace JsonWebToken.Internal
{
    public sealed class Aes128CbcHmac256Encryptor : AesNiCbcHmacEncryptor
    {
        private const int BlockSize = 16;

        private readonly Vector128<byte> _key0;
        private readonly Vector128<byte> _key1;
        private readonly Vector128<byte> _key2;
        private readonly Vector128<byte> _key3;
        private readonly Vector128<byte> _key4;
        private readonly Vector128<byte> _key5;
        private readonly Vector128<byte> _key6;
        private readonly Vector128<byte> _key7;
        private readonly Vector128<byte> _key8;
        private readonly Vector128<byte> _key9;
        private readonly Vector128<byte> _key10;

        public Aes128CbcHmac256Encryptor(SymmetricJwk key)
            : base(key, EncryptionAlgorithm.Aes128CbcHmacSha256)
        {
            if (key.KeySizeInBits < 256)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(key, EncryptionAlgorithm.Aes128CbcHmacSha256, 256, key.KeySizeInBits);
            }

            // extract the 128 last bits of the key
            ref var keyRef = ref MemoryMarshal.GetReference(key.K.Slice(16));
            _key0 = Unsafe.ReadUnaligned<Vector128<byte>>(ref keyRef);
            _key1 = KeyGenAssist(_key0, 0x01);
            _key2 = KeyGenAssist(_key1, 0x02);
            _key3 = KeyGenAssist(_key2, 0x04);
            _key4 = KeyGenAssist(_key3, 0x08);
            _key5 = KeyGenAssist(_key4, 0x10);
            _key6 = KeyGenAssist(_key5, 0x20);
            _key7 = KeyGenAssist(_key6, 0x40);
            _key8 = KeyGenAssist(_key7, 0x80);
            _key9 = KeyGenAssist(_key8, 0x1B);
            _key10 = KeyGenAssist(_key9, 0x36);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> KeyGenAssist(Vector128<byte> key, byte control)
        {
            var keyGened = Aes.KeygenAssist(key, control);
            keyGened = Aes.Shuffle(keyGened.AsInt32(), 0xFF).AsByte();
            key = Aes.Xor(key, Aes.ShiftLeftLogical128BitLane(key, 4));
            key = Aes.Xor(key, Aes.ShiftLeftLogical128BitLane(key, 4));
            key = Aes.Xor(key, Aes.ShiftLeftLogical128BitLane(key, 4));
            return Aes.Xor(key, keyGened);
        }

        /// <inheritsdoc />
        public override void Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, Span<byte> ciphertext, Span<byte> authenticationTag)
        {
            ref var inputRef = ref MemoryMarshal.GetReference(plaintext);
            ref var outputRef = ref MemoryMarshal.GetReference(ciphertext);
            ref var ivRef = ref MemoryMarshal.GetReference(nonce);

            var state = Unsafe.ReadUnaligned<Vector128<byte>>(ref ivRef);
            ref var inputEndRef = ref Unsafe.AddByteOffset(ref inputRef, (IntPtr)plaintext.Length - BlockSize + 1);

            while (Unsafe.IsAddressLessThan(ref inputRef, ref inputEndRef))
            {
                var src = Unsafe.ReadUnaligned<Vector128<byte>>(ref inputRef);
                src = Aes.Xor(src, state);

                state = Aes.Xor(src, _key0);
                state = Aes.Encrypt(state, _key1);
                state = Aes.Encrypt(state, _key2);
                state = Aes.Encrypt(state, _key3);
                state = Aes.Encrypt(state, _key4);
                state = Aes.Encrypt(state, _key5);
                state = Aes.Encrypt(state, _key6);
                state = Aes.Encrypt(state, _key7);
                state = Aes.Encrypt(state, _key8);
                state = Aes.Encrypt(state, _key9);
                state = Aes.EncryptLast(state, _key10);
                Unsafe.WriteUnaligned(ref outputRef, state);

                inputRef = ref Unsafe.AddByteOffset(ref inputRef, (IntPtr)BlockSize);
                outputRef = ref Unsafe.AddByteOffset(ref outputRef, (IntPtr)BlockSize);
            }

            int left = plaintext.Length & 15;

            // Reuse the destination buffer as last block buffer
            Unsafe.CopyBlockUnaligned(ref outputRef, ref inputRef, (uint)left);
            byte padding = (byte)(BlockSize - left);
            Unsafe.InitBlockUnaligned(ref Unsafe.AddByteOffset(ref outputRef, (IntPtr)left), padding, padding);
            var srcLast = Unsafe.ReadUnaligned<Vector128<byte>>(ref outputRef);

            srcLast = Aes.Xor(srcLast, state);

            state = Aes.Xor(srcLast, _key0);
            state = Aes.Encrypt(state, _key1);
            state = Aes.Encrypt(state, _key2);
            state = Aes.Encrypt(state, _key3);
            state = Aes.Encrypt(state, _key4);
            state = Aes.Encrypt(state, _key5);
            state = Aes.Encrypt(state, _key6);
            state = Aes.Encrypt(state, _key7);
            state = Aes.Encrypt(state, _key8);
            state = Aes.Encrypt(state, _key9);
            state = Aes.EncryptLast(state, _key10);
            Unsafe.WriteUnaligned(ref outputRef, state);

            ComputeAuthenticationTag(nonce, associatedData, ciphertext, authenticationTag);
        }
    }

    public sealed class Aes128CbcHmac256Decryptor : AesNiCbcHmacDecryptor
    {
        private const int BlockSize = 16;
        
        private readonly Vector128<byte> _key0;
        private readonly Vector128<byte> _key1;
        private readonly Vector128<byte> _key2;
        private readonly Vector128<byte> _key3;
        private readonly Vector128<byte> _key4;
        private readonly Vector128<byte> _key5;
        private readonly Vector128<byte> _key6;
        private readonly Vector128<byte> _key7;
        private readonly Vector128<byte> _key8;
        private readonly Vector128<byte> _key9;
        private readonly Vector128<byte> _key10;

        public Aes128CbcHmac256Decryptor(SymmetricJwk key)
            : base(key, EncryptionAlgorithm.Aes128CbcHmacSha256)
        {
            if (key.KeySizeInBits < 256)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(key, EncryptionAlgorithm.Aes128CbcHmacSha256, 256, key.KeySizeInBits);
            }

            // extract the 128 last bits of the key
            ref var keyRef = ref MemoryMarshal.GetReference(key.K.Slice(16));

            var tmp = Unsafe.ReadUnaligned<Vector128<byte>>(ref keyRef);
            _key0 = tmp;

            tmp = KeyGenAssist(tmp, 0x01);
            _key9 = Aes.InverseMixColumns(tmp);
            tmp = KeyGenAssist(tmp, 0x02);
            _key8 = Aes.InverseMixColumns(tmp);
            tmp = KeyGenAssist(tmp, 0x04);
            _key7 = Aes.InverseMixColumns(tmp);
            tmp = KeyGenAssist(tmp, 0x08);
            _key6 = Aes.InverseMixColumns(tmp);
            tmp = KeyGenAssist(tmp, 0x10);
            _key5 = Aes.InverseMixColumns(tmp);
            tmp = KeyGenAssist(tmp, 0x20);
            _key4 = Aes.InverseMixColumns(tmp);
            tmp = KeyGenAssist(tmp, 0x40);
            _key3 = Aes.InverseMixColumns(tmp);
            tmp = KeyGenAssist(tmp, 0x80);
            _key2 = Aes.InverseMixColumns(tmp);
            tmp = KeyGenAssist(tmp, 0x1B);
            _key1 = Aes.InverseMixColumns(tmp);
            _key10 = KeyGenAssist(tmp, 0x36);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> KeyGenAssist(Vector128<byte> key, byte control)
        {
            var keyGened = Aes.KeygenAssist(key, control);
            keyGened = Aes.Shuffle(keyGened.AsInt32(), 0xFF).AsByte();
            key = Aes.Xor(key, Aes.ShiftLeftLogical128BitLane(key, 4));
            key = Aes.Xor(key, Aes.ShiftLeftLogical128BitLane(key, 4));
            key = Aes.Xor(key, Aes.ShiftLeftLogical128BitLane(key, 4));
            return Aes.Xor(key, keyGened);
        }

        /// <inheritsdoc />
        public override bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> authenticationTag, Span<byte> plaintext, out int bytesWritten)
        {
            if (VerifyAuthenticationTag(nonce, associatedData, ciphertext, authenticationTag))
            {
                ref var inputRef = ref MemoryMarshal.GetReference(ciphertext);
                ref var outputRef = ref MemoryMarshal.GetReference(plaintext);
                ref var ivRef = ref MemoryMarshal.GetReference(nonce);

                var feedback = Unsafe.ReadUnaligned<Vector128<byte>>(ref ivRef);

                ref var inputEndRef = ref Unsafe.AddByteOffset(ref inputRef, (IntPtr)ciphertext.Length);
                while (Unsafe.IsAddressLessThan(ref inputRef, ref inputEndRef))
                {
                    var block = Unsafe.ReadUnaligned<Vector128<byte>>(ref inputRef);
                    var lastIn = block;
                    var state = Aes.Xor(block, _key10);

                    state = Aes.Decrypt(state, _key1);
                    state = Aes.Decrypt(state, _key2);
                    state = Aes.Decrypt(state, _key3);
                    state = Aes.Decrypt(state, _key4);
                    state = Aes.Decrypt(state, _key5);
                    state = Aes.Decrypt(state, _key6);
                    state = Aes.Decrypt(state, _key7);
                    state = Aes.Decrypt(state, _key8);
                    state = Aes.Decrypt(state, _key9);
                    state = Aes.DecryptLast(state, Aes.Xor(_key0, feedback));

                    Unsafe.WriteUnaligned(ref outputRef, state);

                    feedback = lastIn;

                    inputRef = ref Unsafe.Add(ref inputRef, (IntPtr)BlockSize);
                    outputRef = ref Unsafe.Add(ref outputRef, (IntPtr)BlockSize);
                }

                ref byte paddingRef = ref Unsafe.Subtract(ref outputRef, 1);
                byte padding = paddingRef;

                ref byte lastPadding = ref Unsafe.Subtract(ref outputRef, paddingRef);
                while (Unsafe.IsAddressGreaterThan(ref paddingRef, ref lastPadding))
                {
                    if (padding != paddingRef)
                    {
                        bytesWritten = 0;
                        return false;
                    }

                    paddingRef = ref Unsafe.Subtract(ref paddingRef, 1);
                }

                bytesWritten = ciphertext.Length - paddingRef;
                return true;
            }

            bytesWritten = 0;
            return true;
        }

        public bool TryDecrypt2(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> authenticationTag, Span<byte> plaintext, out int bytesWritten)
        {
            if (VerifyAuthenticationTag(nonce, associatedData, ciphertext, authenticationTag))
            {
                ref var inputRef = ref MemoryMarshal.GetReference(ciphertext);
                ref var outputRef = ref MemoryMarshal.GetReference(plaintext);
                ref var ivRef = ref MemoryMarshal.GetReference(nonce);

                var feedback = Unsafe.ReadUnaligned<Vector128<byte>>(ref ivRef);

                ref var inputEndRef = ref Unsafe.AddByteOffset(ref inputRef, (IntPtr)ciphertext.Length);
                while (Unsafe.IsAddressLessThan(ref inputRef, ref inputEndRef))
                {
                    var block = Unsafe.ReadUnaligned<Vector128<byte>>(ref inputRef);
                    var lastIn = block;
                    var state = Aes.Xor(block, _key10);

                    state = Aes.Decrypt(state, _key1);
                    state = Aes.Decrypt(state, _key2);
                    state = Aes.Decrypt(state, _key3);
                    state = Aes.Decrypt(state, _key4);
                    state = Aes.Decrypt(state, _key5);
                    state = Aes.Decrypt(state, _key6);
                    state = Aes.Decrypt(state, _key7);
                    state = Aes.Decrypt(state, _key8);
                    state = Aes.Decrypt(state, _key9);
                    state = Aes.DecryptLast(state, Aes.Xor(_key0, feedback));

                    Unsafe.WriteUnaligned(ref outputRef, state);

                    feedback = lastIn;

                    inputRef = ref Unsafe.Add(ref inputRef, (IntPtr)BlockSize);
                    outputRef = ref Unsafe.Add(ref outputRef, (IntPtr)BlockSize);
                }

                ref byte paddingRef = ref Unsafe.Subtract(ref outputRef, 1);
                byte padding = paddingRef;

                ref byte lastPadding = ref Unsafe.Subtract(ref outputRef, paddingRef);
                while (Unsafe.IsAddressGreaterThan(ref paddingRef, ref lastPadding))
                {
                    if (padding != paddingRef)
                    {
                        bytesWritten = 0;
                        return false;
                    }

                    paddingRef = ref Unsafe.Subtract(ref paddingRef, 1);
                }

                bytesWritten = ciphertext.Length - paddingRef;
                return true;
            }

            bytesWritten = 0;
            return true;
        }
    }
}
#endif