using System;
using Xunit;

namespace JsonWebToken.Tests.Cryptography
{
    public class Sha512Tests : ShaAlgorithmTest
    {
        protected override void ComputeHash(ReadOnlySpan<byte> source, Span<byte> destination)
        {
            var sha512 = new Sha512();
            sha512.ComputeHash(source, destination);
        }

        protected override void ComputeHash(ReadOnlySpan<byte> source, ReadOnlySpan<byte> preprend, Span<byte> destination)
        {
            var sha512 = new Sha512();
            sha512.ComputeHash(source, preprend, destination);
        }


        [Fact]
        public void Sha512_Empty()
        {
            Verify(
                Array.Empty<byte>(),
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
        }

        // These test cases are from http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf Appendix C
        [Fact]
        public void Sha512_Fips180_1()
        {
            Verify(
                "abc",
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
        }

        [Fact]
        public void Sha512_Fips180_2()
        {
            Verify(
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
        }

        [Fact]
        public void Sha512_Fips180_3()
        {
            Verify(
                'a',
                1000000,
                "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");
        }

        [Fact]
        public void Sha512_Fips180_3_Prepend1()
        {
            Verify(
                'a',
                1000000 - 128,
                'a',
                128,
                "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");
        }

        [Fact]
        public void Sha512_Fips180_3_Prepend2()
        {
            Verify(
                'a',
                1000000 - 1,
                'a',
                1,
                "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");
        }

        [Fact]
        public void Sha512_Fips180_3_Prepend3()
        {
            Verify(
                'a',
                1000000 - 127,
                'a',
                127,
                "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");
        }

        [Fact]
        public void Sha512_Fips180_1_Prepend1()
        {
            Verify(
                "bc",
                "a",
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
        }
    }
}
