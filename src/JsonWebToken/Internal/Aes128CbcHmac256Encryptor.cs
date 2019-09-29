// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

#if NETCOREAPP3_0
using System;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using AesNi = System.Runtime.Intrinsics.X86.Aes;
using System.Runtime.CompilerServices;

namespace JsonWebToken.Internal
{
    public sealed class Aes128CbcHmac256Encryptor : AesNiCbcHmacEncryptor
    {
        private readonly SymmetricJwk _hmacKey;

        private const int BytesPerRoundKey = 16;
        private const int BlockSize = 16;

        private const int NumberOfRoundKeys = 10;

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
        private readonly Vector128<byte> _key11;
        private readonly Vector128<byte> _key12;
        private readonly Vector128<byte> _key13;
        private readonly Vector128<byte> _key14;
        private readonly Vector128<byte> _key15;
        private readonly Vector128<byte> _key16;
        private readonly Vector128<byte> _key17;
        private readonly Vector128<byte> _key18;
        private readonly Vector128<byte> _key19;
        public Aes128CbcHmac256Encryptor(SymmetricJwk key)
            : base(key, EncryptionAlgorithm.Aes128CbcHmacSha256)
        {
            if (key.KeySizeInBits < 256)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(key, EncryptionAlgorithm.Aes128CbcHmacSha256, 256, key.KeySizeInBits);
            }

            int keyLength = EncryptionAlgorithm.Aes128CbcHmacSha256.RequiredKeySizeInBits >> 4;
            var keyBytes = key.K;
            _hmacKey = SymmetricJwk.FromSpan(keyBytes.Slice(0, keyLength), false);

            if (!_hmacKey.TryGetSigner(EncryptionAlgorithm.Aes128CbcHmacSha256.SignatureAlgorithm, out var signer))
            {
                ThrowHelper.ThrowNotSupportedException_SignatureAlgorithm(EncryptionAlgorithm.Aes128CbcHmacSha256.SignatureAlgorithm);
            }

            ref var expandedKey = ref MemoryMarshal.GetReference((Span<byte>)_expandedKey);
            _key0 = Unsafe.ReadUnaligned<Vector128<byte>>(ref expandedKey);
            _key1 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(BytesPerRoundKey * 1)));
            _key2 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(BytesPerRoundKey * 2)));
            _key3 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(BytesPerRoundKey * 3)));
            _key4 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(BytesPerRoundKey * 4)));
            _key5 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(BytesPerRoundKey * 5)));
            _key6 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(BytesPerRoundKey * 6)));
            _key7 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(BytesPerRoundKey * 7)));
            _key8 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(BytesPerRoundKey * 8)));
            _key9 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(BytesPerRoundKey * 9)));
            _key10 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(BytesPerRoundKey * 10)));

            _key11 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(BytesPerRoundKey *  11)));
            _key12 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(BytesPerRoundKey *  12)));
            _key13 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(BytesPerRoundKey *  13)));
            _key14 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(BytesPerRoundKey *  14)));
            _key15 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(BytesPerRoundKey *  15)));
            _key16 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(BytesPerRoundKey *  16)));
            _key17 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(BytesPerRoundKey *  17)));
            _key18 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(BytesPerRoundKey *  18)));
            _key19 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(BytesPerRoundKey * 19)));
        }

        protected override byte[] ExpandKey(ReadOnlySpan<byte> key)
        {
            var keySchedule = new byte[2 * BytesPerRoundKey * NumberOfRoundKeys];
            ref var expandedKey = ref MemoryMarshal.GetReference(keySchedule.AsSpan());
            ref var keyRef = ref MemoryMarshal.GetReference(key);

            var tmp = Unsafe.ReadUnaligned<Vector128<byte>>(ref keyRef);
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(0 * BytesPerRoundKey)), tmp);

            tmp = KeyGenAssist(tmp, 0x01);
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(1 * BytesPerRoundKey)), tmp);
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(19 * BytesPerRoundKey)), AesNi.InverseMixColumns(tmp));

            tmp = KeyGenAssist(tmp, 0x02);
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(2 * BytesPerRoundKey)), tmp);
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(18 * BytesPerRoundKey)), AesNi.InverseMixColumns(tmp));

            tmp = KeyGenAssist(tmp, 0x04);
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(3 * BytesPerRoundKey)), tmp);
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(17 * BytesPerRoundKey)), AesNi.InverseMixColumns(tmp));

            tmp = KeyGenAssist(tmp, 0x08);
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(4 * BytesPerRoundKey)), tmp);
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(16 * BytesPerRoundKey)), AesNi.InverseMixColumns(tmp));

            tmp = KeyGenAssist(tmp, 0x10);
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(5 * BytesPerRoundKey)), tmp);
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(15 * BytesPerRoundKey)), AesNi.InverseMixColumns(tmp));

            tmp = KeyGenAssist(tmp, 0x20);
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(6 * BytesPerRoundKey)), tmp);
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(14 * BytesPerRoundKey)), AesNi.InverseMixColumns(tmp));

            tmp = KeyGenAssist(tmp, 0x40);
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(7 * BytesPerRoundKey)), tmp);
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(13 * BytesPerRoundKey)), AesNi.InverseMixColumns(tmp));

            tmp = KeyGenAssist(tmp, 0x80);
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(8 * BytesPerRoundKey)), tmp);
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(12 * BytesPerRoundKey)), AesNi.InverseMixColumns(tmp));

            tmp = KeyGenAssist(tmp, 0x1B);
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(9 * BytesPerRoundKey)), tmp);
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(11 * BytesPerRoundKey)), AesNi.InverseMixColumns(tmp));

            tmp = KeyGenAssist(tmp, 0x36);
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr)(10 * BytesPerRoundKey)), tmp);

            return keySchedule;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> KeyGenAssist(Vector128<byte> key, byte control)
        {
            var keyGened = AesNi.KeygenAssist(key, control);
            keyGened = Sse2.Shuffle(keyGened.AsInt32(), 0xFF).AsByte();
            key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
            key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
            key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
            return Sse2.Xor(key, keyGened);
        }

        public override void Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, Span<byte> ciphertext, Span<byte> authenticationTag)
        {
            if (AesNi.IsSupported)
            {
                ref var inputRef = ref MemoryMarshal.GetReference(plaintext);
                ref var outputRef = ref MemoryMarshal.GetReference(ciphertext);
                ref var ivRef = ref MemoryMarshal.GetReference(nonce);

                var state = Unsafe.ReadUnaligned<Vector128<byte>>(ref ivRef);
                ref var inputEndRef = ref Unsafe.AddByteOffset(ref inputRef, (IntPtr)plaintext.Length - BlockSize + 1);

                while (Unsafe.IsAddressLessThan(ref inputRef, ref inputEndRef))
                {
                    var src = Unsafe.ReadUnaligned<Vector128<byte>>(ref inputRef);
                    src = AesNi.Xor(src, state);

                    state = AesNi.Xor(src, _key0);
                    state = AesNi.Encrypt(state, _key1);
                    state = AesNi.Encrypt(state, _key2);
                    state = AesNi.Encrypt(state, _key3);
                    state = AesNi.Encrypt(state, _key4);
                    state = AesNi.Encrypt(state, _key5);
                    state = AesNi.Encrypt(state, _key6);
                    state = AesNi.Encrypt(state, _key7);
                    state = AesNi.Encrypt(state, _key8);
                    state = AesNi.Encrypt(state, _key9);
                    state = AesNi.EncryptLast(state, _key10);
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

                srcLast = AesNi.Xor(srcLast, state);

                state = AesNi.Xor(srcLast, _key0);
                state = AesNi.Encrypt(state, _key1);
                state = AesNi.Encrypt(state, _key2);
                state = AesNi.Encrypt(state, _key3);
                state = AesNi.Encrypt(state, _key4);
                state = AesNi.Encrypt(state, _key5);
                state = AesNi.Encrypt(state, _key6);
                state = AesNi.Encrypt(state, _key7);
                state = AesNi.Encrypt(state, _key8);
                state = AesNi.Encrypt(state, _key9);
                state = AesNi.EncryptLast(state, _key10);
                Unsafe.WriteUnaligned(ref outputRef, state);

                SignData(nonce, associatedData, ciphertext, authenticationTag);
            }
            else
            {
                _fallbackEncryptor!.Encrypt(plaintext, nonce, associatedData, ciphertext, authenticationTag);
            }
        }

        public override bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> authenticationTag, Span<byte> plaintext, out int bytesWritten)
        {
            if (AesNi.IsSupported)
            {
                if (ValidateSignature(nonce, associatedData, ciphertext, authenticationTag))
                {
                    ref var inputRef = ref MemoryMarshal.GetReference(ciphertext);
                    ref var outputRef = ref MemoryMarshal.GetReference(plaintext);
                    ref var ivRef = ref MemoryMarshal.GetReference(nonce);

                    var feedback0 = Unsafe.ReadUnaligned<Vector128<byte>>(ref ivRef);

                    ref var inputEndRef = ref Unsafe.AddByteOffset(ref inputRef, (IntPtr)ciphertext.Length);
                    while (Unsafe.IsAddressLessThan(ref inputRef, ref inputEndRef))
                    {
                        var block = Unsafe.ReadUnaligned<Vector128<byte>>(ref inputRef);
                        var lastIn = block;
                        var state = AesNi.Xor(block, _key10);

                        state = AesNi.Decrypt(state, _key11);
                        state = AesNi.Decrypt(state, _key12);
                        state = AesNi.Decrypt(state, _key13);
                        state = AesNi.Decrypt(state, _key14);
                        state = AesNi.Decrypt(state, _key15);
                        state = AesNi.Decrypt(state, _key16);
                        state = AesNi.Decrypt(state, _key17);
                        state = AesNi.Decrypt(state, _key18);
                        state = AesNi.Decrypt(state, _key19);
                        state = AesNi.DecryptLast(state, AesNi.Xor(_key0, feedback0));

                        Unsafe.WriteUnaligned(ref outputRef, state);

                        feedback0 = lastIn;

                        inputRef = ref Unsafe.Add(ref inputRef, (IntPtr)BlockSize);
                        outputRef = ref Unsafe.Add(ref outputRef, (IntPtr)BlockSize);
                        //left -= BlockSize;
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
            else
            {
                return _fallbackEncryptor.TryDecrypt(ciphertext, associatedData, nonce, authenticationTag, plaintext, out bytesWritten);
            }
        }
    }
}
#endif