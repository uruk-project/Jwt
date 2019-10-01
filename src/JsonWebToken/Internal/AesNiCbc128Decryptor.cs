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
    public sealed class AesNiCbc128Decryptor : AesDecryptor
    {
        private const int BlockSize = 16;

        private Vector128<byte> _key0;
        private Vector128<byte> _key1;
        private Vector128<byte> _key2;
        private Vector128<byte> _key3;
        private Vector128<byte> _key4;
        private Vector128<byte> _key5;
        private Vector128<byte> _key6;
        private Vector128<byte> _key7;
        private Vector128<byte> _key8;
        private Vector128<byte> _key9;
        private Vector128<byte> _key10;

        public AesNiCbc128Decryptor(ReadOnlySpan<byte> key)
        {
            if (key.Length < 16)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(EncryptionAlgorithm.Aes128CbcHmacSha256, 256, 16);
            }

            // extract the 128 last bits of the key
            ref var keyRef = ref MemoryMarshal.GetReference(key);

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

        public override void Dispose()
        {
            // Clear the keys
            _key0 = Vector128<byte>.Zero;
            _key1 = Vector128<byte>.Zero;
            _key2 = Vector128<byte>.Zero;
            _key3 = Vector128<byte>.Zero;
            _key4 = Vector128<byte>.Zero;
            _key5 = Vector128<byte>.Zero;
            _key6 = Vector128<byte>.Zero;
            _key7 = Vector128<byte>.Zero;
            _key8 = Vector128<byte>.Zero;
            _key9 = Vector128<byte>.Zero;
            _key10 = Vector128<byte>.Zero;
        }

        public override bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, Span<byte> plaintext, out int bytesWritten)
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
    }
}
#endif