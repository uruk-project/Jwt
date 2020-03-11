using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using JsonWebToken.Internal;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class AesDecryptorBenchmark
    {
        private static AesCbcEncryptor _encryptor;
        private static AesCbcDecryptor _decryptor;
#if NETCOREAPP3_0
        private static AesNiCbc128Decryptor_Old _decryptorNi_Old;
        private static AesNiCbc128Decryptor_New _decryptorNi_New;
#endif
        private static byte[] plaintext;
        private static byte[] nonce;

        static AesDecryptorBenchmark()
        {
            plaintext = new byte[2048 * 16 + 16];
            var key = SymmetricJwk.GenerateKey(256);
            nonce = new byte[] { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
            _encryptor = new AesCbcEncryptor(key.K.Slice(16), EncryptionAlgorithm.Aes128CbcHmacSha256);
            _decryptor = new AesCbcDecryptor(key.K.Slice(16), EncryptionAlgorithm.Aes128CbcHmacSha256);
#if NETCOREAPP3_0
            _decryptorNi_Old = new AesNiCbc128Decryptor_Old(key.K.Slice(16));
            _decryptorNi_New = new AesNiCbc128Decryptor_New(key.K.Slice(16));
#endif
        }

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetData))]
        public bool Decrypt(byte[] ciphertext)
        {
            return _decryptor!.TryDecrypt(ciphertext, nonce, plaintext, out int bytesWritten);
        }

#if NETCOREAPP3_0
        [Benchmark(Baseline = false)]
        [ArgumentsSource(nameof(GetData))]
        public bool Decrypt_Simd_Old(byte[] ciphertext)
        {
            return _decryptorNi_Old!.TryDecrypt(ciphertext, nonce, plaintext, out int bytesWritten);
        }

        [Benchmark(Baseline = false)]
        [ArgumentsSource(nameof(GetData))]
        public bool Decrypt_Simd_New(byte[] ciphertext)
        {
            return _decryptorNi_New!.TryDecrypt(ciphertext, nonce, plaintext, out int bytesWritten);
        }

        public static IEnumerable<byte[]> GetData()
        {
            yield return GetCiphertext(Encoding.UTF8.GetBytes(Enumerable.Repeat('a', 1).ToArray()));
            yield return GetCiphertext(Encoding.UTF8.GetBytes(Enumerable.Repeat('a', 2048).ToArray()));
            yield return GetCiphertext(Encoding.UTF8.GetBytes(Enumerable.Repeat('a', 2048 * 16).ToArray()));
        }

        private static byte[] GetCiphertext(byte[] plaintext)
        {
           var ciphertext = (new byte[(plaintext.Length + 16) & ~15]);

            _encryptor.Encrypt(plaintext, nonce, ciphertext);
            return ciphertext;
        }

        private sealed class AesNiCbc128Decryptor_New : AesDecryptor
        {
            private const int BlockSize = 16;

            private readonly Aes128DecryptionKeys _keys;

            public AesNiCbc128Decryptor_New(ReadOnlySpan<byte> key)
            {
                _keys = new Aes128DecryptionKeys(key);
            }

            public override void Dispose()
            {
                // Clear the keys
                _keys.Clear();
            }

            public override void DecryptBlock(ref byte ciphertext, ref byte plaintext)
            {
                var block = Unsafe.ReadUnaligned<Vector128<byte>>(ref ciphertext);

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
                block = Aes.DecryptLast(block, _keys.Key10);
                Unsafe.WriteUnaligned(ref plaintext, block);
            }

            public override unsafe bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, Span<byte> plaintext, out int bytesWritten)
            {
                ref byte input = ref MemoryMarshal.GetReference(ciphertext);
                ref byte output = ref MemoryMarshal.GetReference(plaintext);
                Vector128<byte> state = default;
                var feedback = Unsafe.As<byte, Vector128<byte>>(ref MemoryMarshal.GetReference(nonce));

                IntPtr offset = (IntPtr)0;
                while ((byte*)offset < (byte*)ciphertext.Length)
                {
                    var block = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref input, offset));
                    var lastIn = block;
                    state = Sse2.Xor(block, _keys.Key0);

                    state = Aes.Decrypt(state, _keys.Key1);
                    state = Aes.Decrypt(state, _keys.Key2);
                    state = Aes.Decrypt(state, _keys.Key3);
                    state = Aes.Decrypt(state, _keys.Key4);
                    state = Aes.Decrypt(state, _keys.Key5);
                    state = Aes.Decrypt(state, _keys.Key6);
                    state = Aes.Decrypt(state, _keys.Key7);
                    state = Aes.Decrypt(state, _keys.Key8);
                    state = Aes.Decrypt(state, _keys.Key9);
                    state = Aes.DecryptLast(state, Sse2.Xor(_keys.Key10, feedback));

                    Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref output, offset), state);

                    feedback = lastIn;

                    offset += BlockSize;
                }

                byte padding = Unsafe.AddByteOffset(ref output, offset - 1);
                if (padding > BlockSize)
                {
                    goto Invalid;
                }

                var mask = GetPaddingMask(padding);
                if (!Sse2.And(mask, state).Equals(mask))
                {
                    goto Invalid;
                }

                bytesWritten = ciphertext.Length - padding;
                return true;

            Invalid:
                bytesWritten = 0;
                return false;
            }

            private readonly struct Aes128DecryptionKeys
            {
                private const int Count = 11;

                public readonly Vector128<byte> Key0;
                public readonly Vector128<byte> Key1;
                public readonly Vector128<byte> Key2;
                public readonly Vector128<byte> Key3;
                public readonly Vector128<byte> Key4;
                public readonly Vector128<byte> Key5;
                public readonly Vector128<byte> Key6;
                public readonly Vector128<byte> Key7;
                public readonly Vector128<byte> Key8;
                public readonly Vector128<byte> Key9;
                public readonly Vector128<byte> Key10;

                public Aes128DecryptionKeys(ReadOnlySpan<byte> key)
                {
                    if (key.Length != 16)
                    {
                        ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(EncryptionAlgorithm.Aes128CbcHmacSha256, 128, key.Length * 8);
                    }

                    var tmp = Unsafe.ReadUnaligned<Vector128<byte>>(ref MemoryMarshal.GetReference(key));
                    Key10 = tmp;

                    tmp = KeyGenAssist(tmp, 0x01);
                    Key9 = Aes.InverseMixColumns(tmp);
                    tmp = KeyGenAssist(tmp, 0x02);
                    Key8 = Aes.InverseMixColumns(tmp);
                    tmp = KeyGenAssist(tmp, 0x04);
                    Key7 = Aes.InverseMixColumns(tmp);
                    tmp = KeyGenAssist(tmp, 0x08);
                    Key6 = Aes.InverseMixColumns(tmp);
                    tmp = KeyGenAssist(tmp, 0x10);
                    Key5 = Aes.InverseMixColumns(tmp);
                    tmp = KeyGenAssist(tmp, 0x20);
                    Key4 = Aes.InverseMixColumns(tmp);
                    tmp = KeyGenAssist(tmp, 0x40);
                    Key3 = Aes.InverseMixColumns(tmp);
                    tmp = KeyGenAssist(tmp, 0x80);
                    Key2 = Aes.InverseMixColumns(tmp);
                    tmp = KeyGenAssist(tmp, 0x1B);
                    Key1 = Aes.InverseMixColumns(tmp);
                    Key0 = KeyGenAssist(tmp, 0x36);
                }

                [MethodImpl(MethodImplOptions.AggressiveInlining)]
                private static Vector128<byte> KeyGenAssist(Vector128<byte> key, byte control)
                {
                    var keyGened = Aes.KeygenAssist(key, control);
                    keyGened = Sse2.Shuffle(keyGened.AsInt32(), 0xFF).AsByte();
                    key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
                    key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
                    key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
                    return Sse2.Xor(key, keyGened);
                }

                public void Clear()
                {
                    ref byte that = ref Unsafe.As<Aes128DecryptionKeys, byte>(ref Unsafe.AsRef(this));
                    Unsafe.InitBlock(ref that, 0, Count * 16);
                }
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static Vector128<byte> GetPaddingMask(byte padding)
            {
                ref Vector128<byte> tmp = ref Unsafe.As<byte, Vector128<byte>>(ref MemoryMarshal.GetReference(PaddingMask));
                return Unsafe.Add(ref tmp, (IntPtr)padding);
            }

            private static ReadOnlySpan<byte> PaddingMask => new byte[17 * 16]
            {
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x02,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x03,0x03,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x04,0x04,0x04,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x05,0x05,0x05,0x05,0x05,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x06,0x06,0x06,0x06,0x06,0x06,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x07,0x07,0x07,0x07,0x07,0x07,0x07,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x08,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x09,0x09,0x09,0x09,0x09,0x09,0x09,0x09,0x09,
                0x00,0x00,0x00,0x00,0x00,0x00,0x0A,0x0A,0x0A,0x0A,0x0A,0x0A,0x0A,0x0A,0x0A,0x0A,
                0x00,0x00,0x00,0x00,0x00,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,
                0x00,0x00,0x00,0x00,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,
                0x00,0x00,0x00,0x0D,0x0D,0x0D,0x0D,0x0D,0x0D,0x0D,0x0D,0x0D,0x0D,0x0D,0x0D,0x0D,
                0x00,0x00,0x0E,0x0E,0x0E,0x0E,0x0E,0x0E,0x0E,0x0E,0x0E,0x0E,0x0E,0x0E,0x0E,0x0E,
                0x00,0x0F,0x0F,0x0F,0x0F,0x0F,0x0F,0x0F,0x0F,0x0F,0x0F,0x0F,0x0F,0x0F,0x0F,0x0F,
                0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10
            };
        }

        internal sealed class AesNiCbc128Decryptor_Old : AesDecryptor
        {
            private const int BlockSize = 16;

            private readonly Aes128DecryptionKeys _keys;

            public AesNiCbc128Decryptor_Old(ReadOnlySpan<byte> key)
            {
                _keys = new Aes128DecryptionKeys(key);
            }

            public override void Dispose()
            {
                // Clear the keys
                _keys.Clear();
            }

            public override unsafe void DecryptBlock(ref byte ciphertext, ref byte plaintext)
            {
                var block = Unsafe.ReadUnaligned<Vector128<byte>>(ref ciphertext);

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
                block = Aes.DecryptLast(block, _keys.Key10);
                Unsafe.WriteUnaligned(ref plaintext, block);
            }

            public override bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, Span<byte> plaintext, out int bytesWritten)
            {
                ref var inputRef = ref MemoryMarshal.GetReference(ciphertext);
                ref var outputRef = ref MemoryMarshal.GetReference(plaintext);
                ref var ivRef = ref MemoryMarshal.GetReference(nonce);
                Vector128<byte> state = default;
                var feedback = Unsafe.ReadUnaligned<Vector128<byte>>(ref ivRef);
                int i = 0;
                ref var inputEndRef = ref Unsafe.AddByteOffset(ref inputRef, (IntPtr)ciphertext.Length);
                while (Unsafe.IsAddressLessThan(ref inputRef, ref inputEndRef))
                {
                    var block = Unsafe.ReadUnaligned<Vector128<byte>>(ref inputRef);
                    var lastIn = block;
                    state = Sse2.Xor(block, _keys.Key0);

                    state = Aes.Decrypt(state, _keys.Key1);
                    state = Aes.Decrypt(state, _keys.Key2);
                    state = Aes.Decrypt(state, _keys.Key3);
                    state = Aes.Decrypt(state, _keys.Key4);
                    state = Aes.Decrypt(state, _keys.Key5);
                    state = Aes.Decrypt(state, _keys.Key6);
                    state = Aes.Decrypt(state, _keys.Key7);
                    state = Aes.Decrypt(state, _keys.Key8);
                    state = Aes.Decrypt(state, _keys.Key9);
                    state = Aes.DecryptLast(state, Sse2.Xor(_keys.Key10, feedback));

                    Unsafe.WriteUnaligned(ref outputRef, state);

                    feedback = lastIn;

                    inputRef = ref Unsafe.Add(ref inputRef, (IntPtr)BlockSize);
                    outputRef = ref Unsafe.Add(ref outputRef, (IntPtr)BlockSize);
                    i += BlockSize;
                }

                ref byte paddingRef = ref Unsafe.Subtract(ref outputRef, 1);
                byte padding = paddingRef;
                var mask = Vector128.Create(padding);
                mask = Sse2.ShiftLeftLogical128BitLane(mask, (byte)(BlockSize - padding));

                if (!Sse2.And(mask, state).Equals(mask))
                {
                    bytesWritten = 0;
                    return false;
                }

                bytesWritten = ciphertext.Length - paddingRef;
                return true;
            }

            private readonly struct Aes128DecryptionKeys
            {
                private const int Count = 11;

                public readonly Vector128<byte> Key0;
                public readonly Vector128<byte> Key1;
                public readonly Vector128<byte> Key2;
                public readonly Vector128<byte> Key3;
                public readonly Vector128<byte> Key4;
                public readonly Vector128<byte> Key5;
                public readonly Vector128<byte> Key6;
                public readonly Vector128<byte> Key7;
                public readonly Vector128<byte> Key8;
                public readonly Vector128<byte> Key9;
                public readonly Vector128<byte> Key10;

                public Aes128DecryptionKeys(ReadOnlySpan<byte> key)
                {
                    if (key.Length != 16)
                    {
                        ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(EncryptionAlgorithm.Aes128CbcHmacSha256, 128, key.Length * 8);
                    }

                    ref var keyRef = ref MemoryMarshal.GetReference(key);

                    var tmp = Unsafe.ReadUnaligned<Vector128<byte>>(ref keyRef);
                    Key10 = tmp;

                    tmp = KeyGenAssist(tmp, 0x01);
                    Key9 = Aes.InverseMixColumns(tmp);
                    tmp = KeyGenAssist(tmp, 0x02);
                    Key8 = Aes.InverseMixColumns(tmp);
                    tmp = KeyGenAssist(tmp, 0x04);
                    Key7 = Aes.InverseMixColumns(tmp);
                    tmp = KeyGenAssist(tmp, 0x08);
                    Key6 = Aes.InverseMixColumns(tmp);
                    tmp = KeyGenAssist(tmp, 0x10);
                    Key5 = Aes.InverseMixColumns(tmp);
                    tmp = KeyGenAssist(tmp, 0x20);
                    Key4 = Aes.InverseMixColumns(tmp);
                    tmp = KeyGenAssist(tmp, 0x40);
                    Key3 = Aes.InverseMixColumns(tmp);
                    tmp = KeyGenAssist(tmp, 0x80);
                    Key2 = Aes.InverseMixColumns(tmp);
                    tmp = KeyGenAssist(tmp, 0x1B);
                    Key1 = Aes.InverseMixColumns(tmp);
                    Key0 = KeyGenAssist(tmp, 0x36);
                }

                [MethodImpl(MethodImplOptions.AggressiveInlining)]
                private static Vector128<byte> KeyGenAssist(Vector128<byte> key, byte control)
                {
                    var keyGened = Aes.KeygenAssist(key, control);
                    keyGened = Sse2.Shuffle(keyGened.AsInt32(), 0xFF).AsByte();
                    key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
                    key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
                    key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
                    return Sse2.Xor(key, keyGened);
                }

                public void Clear()
                {
                    ref byte that = ref Unsafe.As<Aes128DecryptionKeys, byte>(ref Unsafe.AsRef(this));
                    Unsafe.InitBlock(ref that, 0, Count * 16);
                }
            }
        }
#endif
    }
}
