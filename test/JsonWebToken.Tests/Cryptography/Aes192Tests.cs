﻿using JsonWebToken.Cryptography;
using Xunit;

namespace JsonWebToken.Tests.Cryptography
{
    public class Aes192Tests : AesTests
    {
        [Theory]
        [InlineData("1b077a6af4b7f98229de786d7516b639", "275cfc0413d8ccb70513c3859b1d0f72")]
        [InlineData("9c2d8842e5f48f57648205d39a239af1", "c9b8135ff1b5adc413dfd053b21bd96d")]
        [InlineData("bff52510095f518ecca60af4205444bb", "4a3650c3371ce2eb35e389a171427440")]
        [InlineData("51719783d3185a535bd75adc65071ce1", "4f354592ff7c8847d2d0870ca9481b7c")]
        [InlineData("26aa49dcfe7629a8901a69a9914e6dfd", "d5e08bf9a182e857cf40b3a36ee248cc")]
        [InlineData("941a4773058224e1ef66d10e0a6ee782", "067cd9d3749207791841562507fa9626")]
        public void GfsBoxKatv(string plaintext, string expectedCiphertext)
        {
            VerifyGfsBoxKat(plaintext.HexToByteArray(), expectedCiphertext.HexToByteArray(), "000000000000000000000000000000000000000000000000".HexToByteArray());
        }

        [Theory]
        [InlineData("e9f065d7c13573587f7875357dfbb16c53489f6a4bd0f7cd", "0956259c9cd5cfd0181cca53380cde06")]
        [InlineData("15d20f6ebc7e649fd95b76b107e6daba967c8a9484797f29", "8e4e18424e591a3d5b6f0876f16f8594")]
        [InlineData("a8a282ee31c03fae4f8e9b8930d5473c2ed695a347e88b7c", "93f3270cfc877ef17e106ce938979cb0")]
        [InlineData("cd62376d5ebb414917f0c78f05266433dc9192a1ec943300", "7f6c25ff41858561bb62f36492e93c29")]
        [InlineData("502a6ab36984af268bf423c7f509205207fc1552af4a91e5", "8e06556dcbb00b809a025047cff2a940")]
        [InlineData("25a39dbfd8034f71a81f9ceb55026e4037f8f6aa30ab44ce", "3608c344868e94555d23a120f8a5502d")]
        [InlineData("e08c15411774ec4a908b64eadc6ac4199c7cd453f3aaef53", "77da2021935b840b7f5dcc39132da9e5")]
        [InlineData("3b375a1ff7e8d44409696e6326ec9dec86138e2ae010b980", "3b7c24f825e3bf9873c9f14d39a0e6f4")]
        [InlineData("950bb9f22cc35be6fe79f52c320af93dec5bc9c0c2f9cd53", "64ebf95686b353508c90ecd8b6134316")]
        [InlineData("7001c487cc3e572cfc92f4d0e697d982e8856fdcc957da40", "ff558c5d27210b7929b73fc708eb4cf1")]
        [InlineData("f029ce61d4e5a405b41ead0a883cc6a737da2cf50a6c92ae", "a2c3b2a818075490a7b4c14380f02702")]
        [InlineData("61257134a518a0d57d9d244d45f6498cbc32f2bafc522d79", "cfe4d74002696ccf7d87b14a2f9cafc9")]
        [InlineData("b0ab0a6a818baef2d11fa33eac947284fb7d748cfb75e570", "d2eafd86f63b109b91f5dbb3a3fb7e13")]
        [InlineData("ee053aa011c8b428cdcc3636313c54d6a03cac01c71579d6", "9b9fdd1c5975655f539998b306a324af")]
        [InlineData("d2926527e0aa9f37b45e2ec2ade5853ef807576104c7ace3", "dd619e1cf204446112e0af2b9afa8f8c")]
        [InlineData("982215f4e173dfa0fcffe5d3da41c4812c7bcc8ed3540f93", "d4f0aae13c8fe9339fbf9e69ed0ad74d")]
        [InlineData("98c6b8e01e379fbd14e61af6af891596583565f2a27d59e9", "19c80ec4a6deb7e5ed1033dda933498f")]
        [InlineData("b3ad5cea1dddc214ca969ac35f37dae1a9a9d1528f89bb35", "3cf5e1d21a17956d1dffad6a7c41c659")]
        [InlineData("45899367c3132849763073c435a9288a766c8b9ec2308516", "69fd12e8505f8ded2fdcb197a121b362")]
        [InlineData("ec250e04c3903f602647b85a401a1ae7ca2f02f67fa4253e", "8aa584e2cc4d17417a97cb9a28ba29c8")]
        [InlineData("d077a03bd8a38973928ccafe4a9d2f455130bd0af5ae46a9", "abc786fb1edb504580c4d882ef29a0c7")]
        [InlineData("d184c36cf0dddfec39e654195006022237871a47c33d3198", "2e19fb60a3e1de0166f483c97824a978")]
        [InlineData("4c6994ffa9dcdc805b60c2c0095334c42d95a8fc0ca5b080", "7656709538dd5fec41e0ce6a0f8e207d")]
        [InlineData("c88f5b00a4ef9a6840e2acaf33f00a3bdc4e25895303fa72", "a67cf333b314d411d3c0ae6e1cfcd8f5")]
        public void KeySboxKat(string key, string expectedCiphertext)
        {
            VerifyKeySboxKat(key.HexToByteArray(), expectedCiphertext.HexToByteArray());
        }

        [Theory]
        [InlineData("80000000000000000000000000000000", "6cd02513e8d4dc986b4afe087a60bd0c")]
        [InlineData("c0000000000000000000000000000000", "2ce1f8b7e30627c1c4519eada44bc436")]
        [InlineData("e0000000000000000000000000000000", "9946b5f87af446f5796c1fee63a2da24")]
        [InlineData("f0000000000000000000000000000000", "2a560364ce529efc21788779568d5555")]
        [InlineData("f8000000000000000000000000000000", "35c1471837af446153bce55d5ba72a0a")]
        [InlineData("fc000000000000000000000000000000", "ce60bc52386234f158f84341e534cd9e")]
        [InlineData("fe000000000000000000000000000000", "8c7c27ff32bcf8dc2dc57c90c2903961")]
        [InlineData("ff000000000000000000000000000000", "32bb6a7ec84499e166f936003d55a5bb")]
        [InlineData("ff800000000000000000000000000000", "a5c772e5c62631ef660ee1d5877f6d1b")]
        [InlineData("ffc00000000000000000000000000000", "030d7e5b64f380a7e4ea5387b5cd7f49")]
        [InlineData("ffe00000000000000000000000000000", "0dc9a2610037009b698f11bb7e86c83e")]
        [InlineData("fff00000000000000000000000000000", "0046612c766d1840c226364f1fa7ed72")]
        [InlineData("fff80000000000000000000000000000", "4880c7e08f27befe78590743c05e698b")]
        [InlineData("fffc0000000000000000000000000000", "2520ce829a26577f0f4822c4ecc87401")]
        [InlineData("fffe0000000000000000000000000000", "8765e8acc169758319cb46dc7bcf3dca")]
        [InlineData("ffff0000000000000000000000000000", "e98f4ba4f073df4baa116d011dc24a28")]
        [InlineData("ffff8000000000000000000000000000", "f378f68c5dbf59e211b3a659a7317d94")]
        [InlineData("ffffc000000000000000000000000000", "283d3b069d8eb9fb432d74b96ca762b4")]
        [InlineData("ffffe000000000000000000000000000", "a7e1842e8a87861c221a500883245c51")]
        [InlineData("fffff000000000000000000000000000", "77aa270471881be070fb52c7067ce732")]
        [InlineData("fffff800000000000000000000000000", "01b0f476d484f43f1aeb6efa9361a8ac")]
        [InlineData("fffffc00000000000000000000000000", "1c3a94f1c052c55c2d8359aff2163b4f")]
        [InlineData("fffffe00000000000000000000000000", "e8a067b604d5373d8b0f2e05a03b341b")]
        [InlineData("ffffff00000000000000000000000000", "a7876ec87f5a09bfea42c77da30fd50e")]
        [InlineData("ffffff80000000000000000000000000", "0cf3e9d3a42be5b854ca65b13f35f48d")]
        [InlineData("ffffffc0000000000000000000000000", "6c62f6bbcab7c3e821c9290f08892dda")]
        [InlineData("ffffffe0000000000000000000000000", "7f5e05bd2068738196fee79ace7e3aec")]
        [InlineData("fffffff0000000000000000000000000", "440e0d733255cda92fb46e842fe58054")]
        [InlineData("fffffff8000000000000000000000000", "aa5d5b1c4ea1b7a22e5583ac2e9ed8a7")]
        [InlineData("fffffffc000000000000000000000000", "77e537e89e8491e8662aae3bc809421d")]
        [InlineData("fffffffe000000000000000000000000", "997dd3e9f1598bfa73f75973f7e93b76")]
        [InlineData("ffffffff000000000000000000000000", "1b38d4f7452afefcb7fc721244e4b72e")]
        [InlineData("ffffffff800000000000000000000000", "0be2b18252e774dda30cdda02c6906e3")]
        [InlineData("ffffffffc00000000000000000000000", "d2695e59c20361d82652d7d58b6f11b2")]
        [InlineData("ffffffffe00000000000000000000000", "902d88d13eae52089abd6143cfe394e9")]
        [InlineData("fffffffff00000000000000000000000", "d49bceb3b823fedd602c305345734bd2")]
        [InlineData("fffffffff80000000000000000000000", "707b1dbb0ffa40ef7d95def421233fae")]
        [InlineData("fffffffffc0000000000000000000000", "7ca0c1d93356d9eb8aa952084d75f913")]
        [InlineData("fffffffffe0000000000000000000000", "f2cbf9cb186e270dd7bdb0c28febc57d")]
        [InlineData("ffffffffff0000000000000000000000", "c94337c37c4e790ab45780bd9c3674a0")]
        [InlineData("ffffffffff8000000000000000000000", "8e3558c135252fb9c9f367ed609467a1")]
        [InlineData("ffffffffffc000000000000000000000", "1b72eeaee4899b443914e5b3a57fba92")]
        [InlineData("ffffffffffe000000000000000000000", "011865f91bc56868d051e52c9efd59b7")]
        [InlineData("fffffffffff000000000000000000000", "e4771318ad7a63dd680f6e583b7747ea")]
        [InlineData("fffffffffff800000000000000000000", "61e3d194088dc8d97e9e6db37457eac5")]
        [InlineData("fffffffffffc00000000000000000000", "36ff1ec9ccfbc349e5d356d063693ad6")]
        [InlineData("fffffffffffe00000000000000000000", "3cc9e9a9be8cc3f6fb2ea24088e9bb19")]
        [InlineData("ffffffffffff00000000000000000000", "1ee5ab003dc8722e74905d9a8fe3d350")]
        [InlineData("ffffffffffff80000000000000000000", "245339319584b0a412412869d6c2eada")]
        [InlineData("ffffffffffffc0000000000000000000", "7bd496918115d14ed5380852716c8814")]
        [InlineData("ffffffffffffe0000000000000000000", "273ab2f2b4a366a57d582a339313c8b1")]
        [InlineData("fffffffffffff0000000000000000000", "113365a9ffbe3b0ca61e98507554168b")]
        [InlineData("fffffffffffff8000000000000000000", "afa99c997ac478a0dea4119c9e45f8b1")]
        [InlineData("fffffffffffffc000000000000000000", "9216309a7842430b83ffb98638011512")]
        [InlineData("fffffffffffffe000000000000000000", "62abc792288258492a7cb45145f4b759")]
        [InlineData("ffffffffffffff000000000000000000", "534923c169d504d7519c15d30e756c50")]
        [InlineData("ffffffffffffff800000000000000000", "fa75e05bcdc7e00c273fa33f6ee441d2")]
        [InlineData("ffffffffffffffc00000000000000000", "7d350fa6057080f1086a56b17ec240db")]
        [InlineData("ffffffffffffffe00000000000000000", "f34e4a6324ea4a5c39a661c8fe5ada8f")]
        [InlineData("fffffffffffffff00000000000000000", "0882a16f44088d42447a29ac090ec17e")]
        [InlineData("fffffffffffffff80000000000000000", "3a3c15bfc11a9537c130687004e136ee")]
        [InlineData("fffffffffffffffc0000000000000000", "22c0a7678dc6d8cf5c8a6d5a9960767c")]
        [InlineData("fffffffffffffffe0000000000000000", "b46b09809d68b9a456432a79bdc2e38c")]
        [InlineData("ffffffffffffffff0000000000000000", "93baaffb35fbe739c17c6ac22eecf18f")]
        [InlineData("ffffffffffffffff8000000000000000", "c8aa80a7850675bc007c46df06b49868")]
        [InlineData("ffffffffffffffffc000000000000000", "12c6f3877af421a918a84b775858021d")]
        [InlineData("ffffffffffffffffe000000000000000", "33f123282c5d633924f7d5ba3f3cab11")]
        [InlineData("fffffffffffffffff000000000000000", "a8f161002733e93ca4527d22c1a0c5bb")]
        [InlineData("fffffffffffffffff800000000000000", "b72f70ebf3e3fda23f508eec76b42c02")]
        [InlineData("fffffffffffffffffc00000000000000", "6a9d965e6274143f25afdcfc88ffd77c")]
        [InlineData("fffffffffffffffffe00000000000000", "a0c74fd0b9361764ce91c5200b095357")]
        [InlineData("ffffffffffffffffff00000000000000", "091d1fdc2bd2c346cd5046a8c6209146")]
        [InlineData("ffffffffffffffffff80000000000000", "e2a37580116cfb71856254496ab0aca8")]
        [InlineData("ffffffffffffffffffc0000000000000", "e0b3a00785917c7efc9adba322813571")]
        [InlineData("ffffffffffffffffffe0000000000000", "733d41f4727b5ef0df4af4cf3cffa0cb")]
        [InlineData("fffffffffffffffffff0000000000000", "a99ebb030260826f981ad3e64490aa4f")]
        [InlineData("fffffffffffffffffff8000000000000", "73f34c7d3eae5e80082c1647524308ee")]
        [InlineData("fffffffffffffffffffc000000000000", "40ebd5ad082345b7a2097ccd3464da02")]
        [InlineData("fffffffffffffffffffe000000000000", "7cc4ae9a424b2cec90c97153c2457ec5")]
        [InlineData("ffffffffffffffffffff000000000000", "54d632d03aba0bd0f91877ebdd4d09cb")]
        [InlineData("ffffffffffffffffffff800000000000", "d3427be7e4d27cd54f5fe37b03cf0897")]
        [InlineData("ffffffffffffffffffffc00000000000", "b2099795e88cc158fd75ea133d7e7fbe")]
        [InlineData("ffffffffffffffffffffe00000000000", "a6cae46fb6fadfe7a2c302a34242817b")]
        [InlineData("fffffffffffffffffffff00000000000", "026a7024d6a902e0b3ffccbaa910cc3f")]
        [InlineData("fffffffffffffffffffff80000000000", "156f07767a85a4312321f63968338a01")]
        [InlineData("fffffffffffffffffffffc0000000000", "15eec9ebf42b9ca76897d2cd6c5a12e2")]
        [InlineData("fffffffffffffffffffffe0000000000", "db0d3a6fdcc13f915e2b302ceeb70fd8")]
        [InlineData("ffffffffffffffffffffff0000000000", "71dbf37e87a2e34d15b20e8f10e48924")]
        [InlineData("ffffffffffffffffffffff8000000000", "c745c451e96ff3c045e4367c833e3b54")]
        [InlineData("ffffffffffffffffffffffc000000000", "340da09c2dd11c3b679d08ccd27dd595")]
        [InlineData("ffffffffffffffffffffffe000000000", "8279f7c0c2a03ee660c6d392db025d18")]
        [InlineData("fffffffffffffffffffffff000000000", "a4b2c7d8eba531ff47c5041a55fbd1ec")]
        [InlineData("fffffffffffffffffffffff800000000", "74569a2ca5a7bd5131ce8dc7cbfbf72f")]
        [InlineData("fffffffffffffffffffffffc00000000", "3713da0c0219b63454035613b5a403dd")]
        [InlineData("fffffffffffffffffffffffe00000000", "8827551ddcc9df23fa72a3de4e9f0b07")]
        [InlineData("ffffffffffffffffffffffff00000000", "2e3febfd625bfcd0a2c06eb460da1732")]
        [InlineData("ffffffffffffffffffffffff80000000", "ee82e6ba488156f76496311da6941deb")]
        [InlineData("ffffffffffffffffffffffffc0000000", "4770446f01d1f391256e85a1b30d89d3")]
        [InlineData("ffffffffffffffffffffffffe0000000", "af04b68f104f21ef2afb4767cf74143c")]
        [InlineData("fffffffffffffffffffffffff0000000", "cf3579a9ba38c8e43653173e14f3a4c6")]
        [InlineData("fffffffffffffffffffffffff8000000", "b3bba904f4953e09b54800af2f62e7d4")]
        [InlineData("fffffffffffffffffffffffffc000000", "fc4249656e14b29eb9c44829b4c59a46")]
        [InlineData("fffffffffffffffffffffffffe000000", "9b31568febe81cfc2e65af1c86d1a308")]
        [InlineData("ffffffffffffffffffffffffff000000", "9ca09c25f273a766db98a480ce8dfedc")]
        [InlineData("ffffffffffffffffffffffffff800000", "b909925786f34c3c92d971883c9fbedf")]
        [InlineData("ffffffffffffffffffffffffffc00000", "82647f1332fe570a9d4d92b2ee771d3b")]
        [InlineData("ffffffffffffffffffffffffffe00000", "3604a7e80832b3a99954bca6f5b9f501")]
        [InlineData("fffffffffffffffffffffffffff00000", "884607b128c5de3ab39a529a1ef51bef")]
        [InlineData("fffffffffffffffffffffffffff80000", "670cfa093d1dbdb2317041404102435e")]
        [InlineData("fffffffffffffffffffffffffffc0000", "7a867195f3ce8769cbd336502fbb5130")]
        [InlineData("fffffffffffffffffffffffffffe0000", "52efcf64c72b2f7ca5b3c836b1078c15")]
        [InlineData("ffffffffffffffffffffffffffff0000", "4019250f6eefb2ac5ccbcae044e75c7e")]
        [InlineData("ffffffffffffffffffffffffffff8000", "022c4f6f5a017d292785627667ddef24")]
        [InlineData("ffffffffffffffffffffffffffffc000", "e9c21078a2eb7e03250f71000fa9e3ed")]
        [InlineData("ffffffffffffffffffffffffffffe000", "a13eaeeb9cd391da4e2b09490b3e7fad")]
        [InlineData("fffffffffffffffffffffffffffff000", "c958a171dca1d4ed53e1af1d380803a9")]
        [InlineData("fffffffffffffffffffffffffffff800", "21442e07a110667f2583eaeeee44dc8c")]
        [InlineData("fffffffffffffffffffffffffffffc00", "59bbb353cf1dd867a6e33737af655e99")]
        [InlineData("fffffffffffffffffffffffffffffe00", "43cd3b25375d0ce41087ff9fe2829639")]
        [InlineData("ffffffffffffffffffffffffffffff00", "6b98b17e80d1118e3516bd768b285a84")]
        [InlineData("ffffffffffffffffffffffffffffff80", "ae47ed3676ca0c08deea02d95b81db58")]
        [InlineData("ffffffffffffffffffffffffffffffc0", "34ec40dc20413795ed53628ea748720b")]
        [InlineData("ffffffffffffffffffffffffffffffe0", "4dc68163f8e9835473253542c8a65d46")]
        [InlineData("fffffffffffffffffffffffffffffff0", "2aabb999f43693175af65c6c612c46fb")]
        [InlineData("fffffffffffffffffffffffffffffff8", "e01f94499dac3547515c5b1d756f0f58")]
        [InlineData("fffffffffffffffffffffffffffffffc", "9d12435a46480ce00ea349f71799df9a")]
        [InlineData("fffffffffffffffffffffffffffffffe", "cef41d16d266bdfe46938ad7884cc0cf")]
        [InlineData("ffffffffffffffffffffffffffffffff", "b13db4da1f718bc6904797c82bcf2d32")]
        public void KeyVarTxtKat(string plaintext, string expectedCiphertext)
        {
            VerifyVarTxtKat("000000000000000000000000000000000000000000000000".HexToByteArray(), plaintext.HexToByteArray(), "00000000000000000000000000000000".HexToByteArray(), expectedCiphertext.HexToByteArray());
        }

        [Fact]
        public void EmptySpan()
        {
            VerifyEmptySpan("000000000000000000000000000000000000000000000000".HexToByteArray(), "00000000000000000000000000000000".HexToByteArray());
        }

        private protected override AesDecryptor CreateDecryptor()
            => new AesCbcDecryptor(EncryptionAlgorithm.A192CbcHS384);

        private protected override AesEncryptor CreateEncryptor()
            => new AesCbcEncryptor(EncryptionAlgorithm.A192CbcHS384);
    }
}
