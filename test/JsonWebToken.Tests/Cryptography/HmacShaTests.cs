using System;
using System.Security.Cryptography;
using Xunit;

namespace JsonWebToken.Tests.Cryptography
{
    public abstract class HmacShaTests
    {
        private readonly byte[][] _testKeys =
        {
            null,
            ByteUtils.RepeatByte(0x0b, 20),
            ByteUtils.AsciiBytes("Jefe"),
            ByteUtils.RepeatByte(0xaa, 20),
            ByteUtils.HexToByteArray("0102030405060708090a0b0c0d0e0f10111213141516171819"),
            ByteUtils.HexToByteArray("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"),
            ByteUtils.RepeatByte(0xaa, 131),
            ByteUtils.RepeatByte(0xaa, 131),
        };
        private readonly byte[][] _testData =
        {
            null,
            ByteUtils.AsciiBytes("Hi There"),
            ByteUtils.AsciiBytes("what do ya want for nothing?"),
            ByteUtils.RepeatByte(0xdd, 50),
            ByteUtils.RepeatByte(0xcd, 50),
            ByteUtils.AsciiBytes("Test With Truncation"),
            ByteUtils.AsciiBytes("Test Using Larger Than Block-Size Key - Hash Key First"),
            ByteUtils.AsciiBytes("This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."),
        };

        protected abstract HmacSha2 Create(ReadOnlySpan<byte> key);

        protected abstract Sha2 CreateShaAlgorithm();

        protected abstract int BlockSize { get; }

        protected void VerifyHmac(
            int testCaseId,
            string digest,
            int truncateSize = -1)
        {
            var hmac = Create(_testKeys[testCaseId]);
            byte[] digestBytes = ByteUtils.HexToByteArray(digest);
            byte[] computedDigest = new byte[hmac.HashSize];
            hmac.ComputeHash(_testData[testCaseId], computedDigest);

            if (truncateSize != -1)
            {
                byte[] tmp = new byte[truncateSize];
                Array.Copy(computedDigest, tmp, truncateSize);
                computedDigest = tmp;
                tmp = new byte[truncateSize];
                Array.Copy(digestBytes, tmp, truncateSize);
                digestBytes = tmp;
            }

            Assert.Equal(digestBytes, computedDigest);
        }

        protected void VerifyHmac_KeyAlreadySet(
            HMAC hmac,
            int testCaseId,
            string digest)
        {
            byte[] digestBytes = ByteUtils.HexToByteArray(digest);
            byte[] computedDigest;

            computedDigest = hmac.ComputeHash(_testData[testCaseId]);
            Assert.Equal(digestBytes, computedDigest);
        }
    }
}
