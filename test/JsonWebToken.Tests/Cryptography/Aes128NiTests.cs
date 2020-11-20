using Xunit;

namespace JsonWebToken.Tests.Cryptography
{
#if SUPPORT_SIMD
    public class Aes128NiTests : Aes128Tests
    {
        private protected override AesDecryptor CreateDecryptor()
          => new Aes128CbcDecryptor();

        private protected override AesEncryptor CreateEncryptor()
            => new Aes128CbcEncryptor();
    }
#endif

    public class Aes128Tests : AesTests
    {
        [Theory]
        [InlineData("f34481ec3cc627bacd5dc3fb08f273e6", "0336763e966d92595a567cc9ce537f5e")]
        [InlineData("9798c4640bad75c7c3227db910174e72", "a9a1631bf4996954ebc093957b234589")]
        [InlineData("96ab5c2ff612d9dfaae8c31f30c42168", "ff4f8391a6a40ca5b25d23bedd44a597")]
        [InlineData("6a118a874519e64e9963798a503f1d35", "dc43be40be0e53712f7e2bf5ca707209")]
        [InlineData("cb9fceec81286ca3e989bd979b0cb284", "92beedab1895a94faa69b632e5cc47ce")]
        [InlineData("b26aeb1874e47ca8358ff22378f09144", "459264f4798f6a78bacb89c15ed3d601")]
        [InlineData("58c8e00b2631686d54eab84b91f0aca1", "08a4e2efec8a8e3312ca7460b9040bbf")]
        public void GfsBoxKatv(string plaintext, string expectedCiphertext)
        {
            VerifyGfsBoxKat(plaintext.HexToByteArray(), expectedCiphertext.HexToByteArray(), "00000000000000000000000000000000".HexToByteArray());
        }

        [Theory]
        [InlineData("10a58869d74be5a374cf867cfb473859", "6d251e6944b051e04eaa6fb4dbf78465")]
        [InlineData("caea65cdbb75e9169ecd22ebe6e54675", "6e29201190152df4ee058139def610bb")]
        [InlineData("a2e2fa9baf7d20822ca9f0542f764a41", "c3b44b95d9d2f25670eee9a0de099fa3")]
        [InlineData("b6364ac4e1de1e285eaf144a2415f7a0", "5d9b05578fc944b3cf1ccf0e746cd581")]
        [InlineData("64cf9c7abc50b888af65f49d521944b2", "f7efc89d5dba578104016ce5ad659c05")]
        [InlineData("47d6742eefcc0465dc96355e851b64d9", "0306194f666d183624aa230a8b264ae7")]
        [InlineData("3eb39790678c56bee34bbcdeccf6cdb5", "858075d536d79ccee571f7d7204b1f67")]
        [InlineData("64110a924f0743d500ccadae72c13427", "35870c6a57e9e92314bcb8087cde72ce")]
        [InlineData("18d8126516f8a12ab1a36d9f04d68e51", "6c68e9be5ec41e22c825b7c7affb4363")]
        [InlineData("f530357968578480b398a3c251cd1093", "f5df39990fc688f1b07224cc03e86cea")]
        [InlineData("da84367f325d42d601b4326964802e8e", "bba071bcb470f8f6586e5d3add18bc66")]
        [InlineData("e37b1c6aa2846f6fdb413f238b089f23", "43c9f7e62f5d288bb27aa40ef8fe1ea8")]
        [InlineData("6c002b682483e0cabcc731c253be5674", "3580d19cff44f1014a7c966a69059de5")]
        [InlineData("143ae8ed6555aba96110ab58893a8ae1", "806da864dd29d48deafbe764f8202aef")]
        [InlineData("b69418a85332240dc82492353956ae0c", "a303d940ded8f0baff6f75414cac5243")]
        [InlineData("71b5c08a1993e1362e4d0ce9b22b78d5", "c2dabd117f8a3ecabfbb11d12194d9d0")]
        [InlineData("e234cdca2606b81f29408d5f6da21206", "fff60a4740086b3b9c56195b98d91a7b")]
        [InlineData("13237c49074a3da078dc1d828bb78c6f", "8146a08e2357f0caa30ca8c94d1a0544")]
        [InlineData("3071a2a48fe6cbd04f1a129098e308f8", "4b98e06d356deb07ebb824e5713f7be3")]
        [InlineData("90f42ec0f68385f2ffc5dfc03a654dce", "7a20a53d460fc9ce0423a7a0764c6cf2")]
        [InlineData("febd9a24d8b65c1c787d50a4ed3619a9", "f4a70d8af877f9b02b4c40df57d45b17")]
        public void KeySboxKat(string key, string expectedCiphertext)
        {
            VerifyKeySboxKat(key.HexToByteArray(), expectedCiphertext.HexToByteArray());
        }

        [Theory]
        [InlineData("80000000000000000000000000000000", "3ad78e726c1ec02b7ebfe92b23d9ec34")]
        [InlineData("c0000000000000000000000000000000", "aae5939c8efdf2f04e60b9fe7117b2c2")]
        [InlineData("e0000000000000000000000000000000", "f031d4d74f5dcbf39daaf8ca3af6e527")]
        [InlineData("f0000000000000000000000000000000", "96d9fd5cc4f07441727df0f33e401a36")]
        [InlineData("f8000000000000000000000000000000", "30ccdb044646d7e1f3ccea3dca08b8c0")]
        [InlineData("fc000000000000000000000000000000", "16ae4ce5042a67ee8e177b7c587ecc82")]
        [InlineData("fe000000000000000000000000000000", "b6da0bb11a23855d9c5cb1b4c6412e0a")]
        [InlineData("ff000000000000000000000000000000", "db4f1aa530967d6732ce4715eb0ee24b")]
        [InlineData("ff800000000000000000000000000000", "a81738252621dd180a34f3455b4baa2f")]
        [InlineData("ffc00000000000000000000000000000", "77e2b508db7fd89234caf7939ee5621a")]
        [InlineData("ffe00000000000000000000000000000", "b8499c251f8442ee13f0933b688fcd19")]
        [InlineData("fff00000000000000000000000000000", "965135f8a81f25c9d630b17502f68e53")]
        [InlineData("fff80000000000000000000000000000", "8b87145a01ad1c6cede995ea3670454f")]
        [InlineData("fffc0000000000000000000000000000", "8eae3b10a0c8ca6d1d3b0fa61e56b0b2")]
        [InlineData("fffe0000000000000000000000000000", "64b4d629810fda6bafdf08f3b0d8d2c5")]
        [InlineData("ffff0000000000000000000000000000", "d7e5dbd3324595f8fdc7d7c571da6c2a")]
        [InlineData("ffff8000000000000000000000000000", "f3f72375264e167fca9de2c1527d9606")]
        [InlineData("ffffc000000000000000000000000000", "8ee79dd4f401ff9b7ea945d86666c13b")]
        [InlineData("ffffe000000000000000000000000000", "dd35cea2799940b40db3f819cb94c08b")]
        [InlineData("fffff000000000000000000000000000", "6941cb6b3e08c2b7afa581ebdd607b87")]
        [InlineData("fffff800000000000000000000000000", "2c20f439f6bb097b29b8bd6d99aad799")]
        [InlineData("fffffc00000000000000000000000000", "625d01f058e565f77ae86378bd2c49b3")]
        [InlineData("fffffe00000000000000000000000000", "c0b5fd98190ef45fbb4301438d095950")]
        [InlineData("ffffff00000000000000000000000000", "13001ff5d99806efd25da34f56be854b")]
        [InlineData("ffffff80000000000000000000000000", "3b594c60f5c8277a5113677f94208d82")]
        [InlineData("ffffffc0000000000000000000000000", "e9c0fc1818e4aa46bd2e39d638f89e05")]
        [InlineData("ffffffe0000000000000000000000000", "f8023ee9c3fdc45a019b4e985c7e1a54")]
        [InlineData("fffffff0000000000000000000000000", "35f40182ab4662f3023baec1ee796b57")]
        [InlineData("fffffff8000000000000000000000000", "3aebbad7303649b4194a6945c6cc3694")]
        [InlineData("fffffffc000000000000000000000000", "a2124bea53ec2834279bed7f7eb0f938")]
        [InlineData("fffffffe000000000000000000000000", "b9fb4399fa4facc7309e14ec98360b0a")]
        [InlineData("ffffffff000000000000000000000000", "c26277437420c5d634f715aea81a9132")]
        [InlineData("ffffffff800000000000000000000000", "171a0e1b2dd424f0e089af2c4c10f32f")]
        [InlineData("ffffffffc00000000000000000000000", "7cadbe402d1b208fe735edce00aee7ce")]
        [InlineData("ffffffffe00000000000000000000000", "43b02ff929a1485af6f5c6d6558baa0f")]
        [InlineData("fffffffff00000000000000000000000", "092faacc9bf43508bf8fa8613ca75dea")]
        [InlineData("fffffffff80000000000000000000000", "cb2bf8280f3f9742c7ed513fe802629c")]
        [InlineData("fffffffffc0000000000000000000000", "215a41ee442fa992a6e323986ded3f68")]
        [InlineData("fffffffffe0000000000000000000000", "f21e99cf4f0f77cea836e11a2fe75fb1")]
        [InlineData("ffffffffff0000000000000000000000", "95e3a0ca9079e646331df8b4e70d2cd6")]
        [InlineData("ffffffffff8000000000000000000000", "4afe7f120ce7613f74fc12a01a828073")]
        [InlineData("ffffffffffc000000000000000000000", "827f000e75e2c8b9d479beed913fe678")]
        [InlineData("ffffffffffe000000000000000000000", "35830c8e7aaefe2d30310ef381cbf691")]
        [InlineData("fffffffffff000000000000000000000", "191aa0f2c8570144f38657ea4085ebe5")]
        [InlineData("fffffffffff800000000000000000000", "85062c2c909f15d9269b6c18ce99c4f0")]
        [InlineData("fffffffffffc00000000000000000000", "678034dc9e41b5a560ed239eeab1bc78")]
        [InlineData("fffffffffffe00000000000000000000", "c2f93a4ce5ab6d5d56f1b93cf19911c1")]
        [InlineData("ffffffffffff00000000000000000000", "1c3112bcb0c1dcc749d799743691bf82")]
        [InlineData("ffffffffffff80000000000000000000", "00c55bd75c7f9c881989d3ec1911c0d4")]
        [InlineData("ffffffffffffc0000000000000000000", "ea2e6b5ef182b7dff3629abd6a12045f")]
        [InlineData("ffffffffffffe0000000000000000000", "22322327e01780b17397f24087f8cc6f")]
        [InlineData("fffffffffffff0000000000000000000", "c9cacb5cd11692c373b2411768149ee7")]
        [InlineData("fffffffffffff8000000000000000000", "a18e3dbbca577860dab6b80da3139256")]
        [InlineData("fffffffffffffc000000000000000000", "79b61c37bf328ecca8d743265a3d425c")]
        [InlineData("fffffffffffffe000000000000000000", "d2d99c6bcc1f06fda8e27e8ae3f1ccc7")]
        [InlineData("ffffffffffffff000000000000000000", "1bfd4b91c701fd6b61b7f997829d663b")]
        [InlineData("ffffffffffffff800000000000000000", "11005d52f25f16bdc9545a876a63490a")]
        [InlineData("ffffffffffffffc00000000000000000", "3a4d354f02bb5a5e47d39666867f246a")]
        [InlineData("ffffffffffffffe00000000000000000", "d451b8d6e1e1a0ebb155fbbf6e7b7dc3")]
        [InlineData("fffffffffffffff00000000000000000", "6898d4f42fa7ba6a10ac05e87b9f2080")]
        [InlineData("fffffffffffffff80000000000000000", "b611295e739ca7d9b50f8e4c0e754a3f")]
        [InlineData("fffffffffffffffc0000000000000000", "7d33fc7d8abe3ca1936759f8f5deaf20")]
        [InlineData("fffffffffffffffe0000000000000000", "3b5e0f566dc96c298f0c12637539b25c")]
        [InlineData("ffffffffffffffff0000000000000000", "f807c3e7985fe0f5a50e2cdb25c5109e")]
        [InlineData("ffffffffffffffff8000000000000000", "41f992a856fb278b389a62f5d274d7e9")]
        [InlineData("ffffffffffffffffc000000000000000", "10d3ed7a6fe15ab4d91acbc7d0767ab1")]
        [InlineData("ffffffffffffffffe000000000000000", "21feecd45b2e675973ac33bf0c5424fc")]
        [InlineData("fffffffffffffffff000000000000000", "1480cb3955ba62d09eea668f7c708817")]
        [InlineData("fffffffffffffffff800000000000000", "66404033d6b72b609354d5496e7eb511")]
        [InlineData("fffffffffffffffffc00000000000000", "1c317a220a7d700da2b1e075b00266e1")]
        [InlineData("fffffffffffffffffe00000000000000", "ab3b89542233f1271bf8fd0c0f403545")]
        [InlineData("ffffffffffffffffff00000000000000", "d93eae966fac46dca927d6b114fa3f9e")]
        [InlineData("ffffffffffffffffff80000000000000", "1bdec521316503d9d5ee65df3ea94ddf")]
        [InlineData("ffffffffffffffffffc0000000000000", "eef456431dea8b4acf83bdae3717f75f")]
        [InlineData("ffffffffffffffffffe0000000000000", "06f2519a2fafaa596bfef5cfa15c21b9")]
        [InlineData("fffffffffffffffffff0000000000000", "251a7eac7e2fe809e4aa8d0d7012531a")]
        [InlineData("fffffffffffffffffff8000000000000", "3bffc16e4c49b268a20f8d96a60b4058")]
        [InlineData("fffffffffffffffffffc000000000000", "e886f9281999c5bb3b3e8862e2f7c988")]
        [InlineData("fffffffffffffffffffe000000000000", "563bf90d61beef39f48dd625fcef1361")]
        [InlineData("ffffffffffffffffffff000000000000", "4d37c850644563c69fd0acd9a049325b")]
        [InlineData("ffffffffffffffffffff800000000000", "b87c921b91829ef3b13ca541ee1130a6")]
        [InlineData("ffffffffffffffffffffc00000000000", "2e65eb6b6ea383e109accce8326b0393")]
        [InlineData("ffffffffffffffffffffe00000000000", "9ca547f7439edc3e255c0f4d49aa8990")]
        [InlineData("fffffffffffffffffffff00000000000", "a5e652614c9300f37816b1f9fd0c87f9")]
        [InlineData("fffffffffffffffffffff80000000000", "14954f0b4697776f44494fe458d814ed")]
        [InlineData("fffffffffffffffffffffc0000000000", "7c8d9ab6c2761723fe42f8bb506cbcf7")]
        [InlineData("fffffffffffffffffffffe0000000000", "db7e1932679fdd99742aab04aa0d5a80")]
        [InlineData("ffffffffffffffffffffff0000000000", "4c6a1c83e568cd10f27c2d73ded19c28")]
        [InlineData("ffffffffffffffffffffff8000000000", "90ecbe6177e674c98de412413f7ac915")]
        [InlineData("ffffffffffffffffffffffc000000000", "90684a2ac55fe1ec2b8ebd5622520b73")]
        [InlineData("ffffffffffffffffffffffe000000000", "7472f9a7988607ca79707795991035e6")]
        [InlineData("fffffffffffffffffffffff000000000", "56aff089878bf3352f8df172a3ae47d8")]
        [InlineData("fffffffffffffffffffffff800000000", "65c0526cbe40161b8019a2a3171abd23")]
        [InlineData("fffffffffffffffffffffffc00000000", "377be0be33b4e3e310b4aabda173f84f")]
        [InlineData("fffffffffffffffffffffffe00000000", "9402e9aa6f69de6504da8d20c4fcaa2f")]
        [InlineData("ffffffffffffffffffffffff00000000", "123c1f4af313ad8c2ce648b2e71fb6e1")]
        [InlineData("ffffffffffffffffffffffff80000000", "1ffc626d30203dcdb0019fb80f726cf4")]
        [InlineData("ffffffffffffffffffffffffc0000000", "76da1fbe3a50728c50fd2e621b5ad885")]
        [InlineData("ffffffffffffffffffffffffe0000000", "082eb8be35f442fb52668e16a591d1d6")]
        [InlineData("fffffffffffffffffffffffff0000000", "e656f9ecf5fe27ec3e4a73d00c282fb3")]
        [InlineData("fffffffffffffffffffffffff8000000", "2ca8209d63274cd9a29bb74bcd77683a")]
        [InlineData("fffffffffffffffffffffffffc000000", "79bf5dce14bb7dd73a8e3611de7ce026")]
        [InlineData("fffffffffffffffffffffffffe000000", "3c849939a5d29399f344c4a0eca8a576")]
        [InlineData("ffffffffffffffffffffffffff000000", "ed3c0a94d59bece98835da7aa4f07ca2")]
        [InlineData("ffffffffffffffffffffffffff800000", "63919ed4ce10196438b6ad09d99cd795")]
        [InlineData("ffffffffffffffffffffffffffc00000", "7678f3a833f19fea95f3c6029e2bc610")]
        [InlineData("ffffffffffffffffffffffffffe00000", "3aa426831067d36b92be7c5f81c13c56")]
        [InlineData("fffffffffffffffffffffffffff00000", "9272e2d2cdd11050998c845077a30ea0")]
        [InlineData("fffffffffffffffffffffffffff80000", "088c4b53f5ec0ff814c19adae7f6246c")]
        [InlineData("fffffffffffffffffffffffffffc0000", "4010a5e401fdf0a0354ddbcc0d012b17")]
        [InlineData("fffffffffffffffffffffffffffe0000", "a87a385736c0a6189bd6589bd8445a93")]
        [InlineData("ffffffffffffffffffffffffffff0000", "545f2b83d9616dccf60fa9830e9cd287")]
        [InlineData("ffffffffffffffffffffffffffff8000", "4b706f7f92406352394037a6d4f4688d")]
        [InlineData("ffffffffffffffffffffffffffffc000", "b7972b3941c44b90afa7b264bfba7387")]
        [InlineData("ffffffffffffffffffffffffffffe000", "6f45732cf10881546f0fd23896d2bb60")]
        [InlineData("fffffffffffffffffffffffffffff000", "2e3579ca15af27f64b3c955a5bfc30ba")]
        [InlineData("fffffffffffffffffffffffffffff800", "34a2c5a91ae2aec99b7d1b5fa6780447")]
        [InlineData("fffffffffffffffffffffffffffffc00", "a4d6616bd04f87335b0e53351227a9ee")]
        [InlineData("fffffffffffffffffffffffffffffe00", "7f692b03945867d16179a8cefc83ea3f")]
        [InlineData("ffffffffffffffffffffffffffffff00", "3bd141ee84a0e6414a26e7a4f281f8a2")]
        [InlineData("ffffffffffffffffffffffffffffff80", "d1788f572d98b2b16ec5d5f3922b99bc")]
        [InlineData("ffffffffffffffffffffffffffffffc0", "0833ff6f61d98a57b288e8c3586b85a6")]
        [InlineData("ffffffffffffffffffffffffffffffe0", "8568261797de176bf0b43becc6285afb")]
        [InlineData("fffffffffffffffffffffffffffffff0", "f9b0fda0c4a898f5b9e6f661c4ce4d07")]
        [InlineData("fffffffffffffffffffffffffffffff8", "8ade895913685c67c5269f8aae42983e")]
        [InlineData("fffffffffffffffffffffffffffffffc", "39bde67d5c8ed8a8b1c37eb8fa9f5ac0")]
        [InlineData("fffffffffffffffffffffffffffffffe", "5c005e72c1418c44f569f2ea33ba54f3")]
        [InlineData("ffffffffffffffffffffffffffffffff", "3f5b8cc9ea855a0afa7347d23e8d664e")]
        public void KeyVarTxtKat(string plaintext, string expectedCiphertext)
        {
            VerifyVarTxtKat("00000000000000000000000000000000".HexToByteArray(), plaintext.HexToByteArray(), "00000000000000000000000000000000".HexToByteArray(), expectedCiphertext.HexToByteArray());
        }

        [Fact]
        public void EmptySpan()
        {
            VerifyEmptySpan("00000000000000000000000000000000".HexToByteArray(), "00000000000000000000000000000000".HexToByteArray());
        }

        private protected override AesDecryptor CreateDecryptor()
            => new AesCbcDecryptor(EncryptionAlgorithm.Aes128CbcHmacSha256);

        private protected override AesEncryptor CreateEncryptor()
            => new AesCbcEncryptor(EncryptionAlgorithm.Aes128CbcHmacSha256);
    }
}
