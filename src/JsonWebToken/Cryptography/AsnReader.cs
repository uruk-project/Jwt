using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace JsonWebToken.Cryptography
{
    internal ref struct AsnReader
    {
        public AsnReader(ReadOnlySpan<byte> bytes)
        {
            _bytes = bytes;
            _index = 0;
            TokenType = AsnTokenType.Undefined;
        }

        private readonly ReadOnlySpan<byte> _bytes;
        private int _index;

        internal AsnTokenType TokenType { get; private set; }

        public bool Read()
        {
            if (_index + 1 >= _bytes.Length)
            {
                return false;
            }

            TokenType = ReadTokenType();
            return true;
        }

        public byte ReadByte()
        {
            return _bytes[_index++];
        }

        public ReadOnlySpan<byte> ReadLengthPrefixedBytes()
        {
            int length = ReadLength();
            if (length <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(length), "length must be positive.");
            }

            if (_bytes.Length - length < 0)
            {
                throw new ArgumentException("Cannot read past end of buffer.");
            }

            var ros = _bytes.Slice(_index, length);
            _index += length;
            return ros;
        }

        public ReadOnlySpan<byte> ReadInteger()
        {
            if (!Read())
            {
                throw new InvalidOperationException("No more data to read.");
            }

            if (TokenType != AsnTokenType.Integer)
            {
                throw new InvalidOperationException($"Expect {AsnTokenType.Integer} structure, got {TokenType}.");
            }

            return ReadLengthPrefixedBytes();
        }

        public AsnReader ReadBitString()
        {
            return new AsnReader(ReadBitStringBytes());
        }   
        
        public ReadOnlySpan<byte> ReadBitStringBytes()
        {
            if (!Read())
            {
                throw new InvalidOperationException("No more data to read.");
            }

            if (TokenType != AsnTokenType.BitString)
            {
                throw new InvalidOperationException($"Expect {AsnTokenType.BitString} structure, got {TokenType}.");
            }

            var source = ReadLengthPrefixedBytes();
            int unusedBitCount = source[0];

            if (source.Length == 1)
            {
                Debug.Assert(unusedBitCount == 0);
                return ReadOnlySpan<byte>.Empty;
            }

            int mask = -1 << unusedBitCount;
            byte lastByte = source[source.Length - 1];
            byte maskedByte = (byte)(lastByte & mask);
            Debug.Assert(maskedByte == lastByte);

            return source.Slice(1);
        }

        public AsnReader ReadOctetString()
        {;
            return new AsnReader(ReadOctetStringBytes());
        }

        public ReadOnlySpan<byte> ReadOctetStringBytes()
        {
            if (!Read())
            {
                throw new InvalidOperationException("No more data to read.");
            }

            if (TokenType != AsnTokenType.OctetString)
            {
                throw new InvalidOperationException($"Expect {AsnTokenType.OctetString} structure, got {TokenType}.");
            }

            return ReadLengthPrefixedBytes();
        }

        public void ReadNull()
        {
            if (!Read())
            {
                throw new InvalidOperationException("No more data to read.");
            }

            if (TokenType != AsnTokenType.Null)
            {
                throw new InvalidOperationException($"Expect {AsnTokenType.Null} structure, got {TokenType}.");
            }

            int length = ReadLength();
            if (length != 0)
            {
                throw new InvalidOperationException("Invalid data, Null length must be 0.");
            }
        }

        public int[] ReadOid()
        {
            if (!Read())
            {
                throw new InvalidOperationException("No more data to read.");
            }

            var oidBytes = ReadLengthPrefixedBytes();
            List<int> result = new List<int>();
            bool first = true;
            int index = 0;
            while (index < oidBytes.Length)
            {
                int subId = 0;
                byte b;
                do
                {
                    b = oidBytes[index++];
                    if ((subId & 0xff000000) != 0)
                    {
                        throw new NotSupportedException("Oid subId > 2^31 not supported.");
                    }
                    subId = (subId << 7) | (b & 0x7f);
                } while ((b & 0x80) != 0);
                if (first)
                {
                    first = false;
                    result.Add(subId / 40);
                    result.Add(subId % 40);
                }
                else
                {
                    result.Add(subId);
                }
            }

            return result.ToArray();
        }

        public AsnReader ReadSequence(bool ignoreTypeValidation = false)
        {
            if (!Read())
            {
                throw new InvalidOperationException("No more data to read.");
            }

            if (!ignoreTypeValidation && TokenType != AsnTokenType.Sequence)
            {
                throw new InvalidOperationException($"Expect {AsnTokenType.Sequence} structure, got {TokenType}.");
            }

            int length = ReadLength();
            int endOffset = _index + length;
            if (endOffset < 0 || endOffset > _bytes.Length)
            {
                throw new InvalidOperationException("Invalid sequence, too long.");
            }

            var reader = new AsnReader(_bytes.Slice(_index, length));
            _index += length;
            return reader;
        }

        private AsnTokenType ReadTokenType()
        {
            byte b = _bytes[_index++];
            int tag = b & 0x1f;
            if (tag == 0x1f)
            {
                // A tag value of 0x1f (31) indicates a tag value of >30 (spec section 8.1.2.4)
                throw new NotSupportedException("Tags of value > 30 not supported.");
            }
            else
            {
                return (AsnTokenType)tag;
            }
        }

        private int ReadLength()
        {
            byte b0 = ReadByte();
            if ((b0 & 0x80) == 0)
            {
                return b0;
            }
            else
            {
                if (b0 == 0xff)
                {
                    throw new InvalidOperationException("Invalid length byte: 0xff");
                }
                int byteCount = b0 & 0x7f;
                if (byteCount == 0)
                {
                    throw new NotSupportedException("Indefinite Form not supported.");
                }
                int result = 0;
                for (int i = 0; i < byteCount; i++)
                {
                    if ((result & 0xff800000) != 0)
                    {
                        throw new NotSupportedException("Length > 2^31 is not supported.");
                    }
                    result = (result << 8) | ReadByte();
                }
                return result;
            }
        }

        internal static byte[] TrimLeadingZeroes(ReadOnlySpan<byte> data, bool align = true)
        {
            int zeroCount = 0;
            while (zeroCount < data.Length && data[zeroCount] == 0)
            {
                zeroCount += 1;
            }

            int newLength = data.Length - zeroCount;
            if (align)
            {
                int remainder = newLength & 0x07;
                if (remainder != 0)
                {
                    newLength += 8 - remainder;
                }
            }

            if (newLength == data.Length)
            {
                return data.ToArray();
            }

            byte[] result;
            if (newLength < data.Length)
            {
                result = data.Slice(data.Length - newLength).ToArray();
            }
            else
            {
                result = new byte[newLength];
                data.CopyTo(result.AsSpan(newLength - data.Length));
            }

            return result;
        }
    }
}
