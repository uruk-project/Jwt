using System;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JweSymmetricTokenTests
    {
        private readonly SymmetricJwk _symmetric128Key = new SymmetricJwk
        {
            K = "LxOcGxlu169Vxa1A7HyelQ"
        };

        private readonly SymmetricJwk _symmetric192Key = new SymmetricJwk
        {
            K = "kVdKe3BiLcrc7LujDzaD-3EdZCVTStnc"
        };

        private readonly SymmetricJwk _symmetric256Key = new SymmetricJwk
        {
            K = "-PYUNdvLXVnc8yJQw7iQkSlNmAb202ZO-rfCyrAc1Lo"
        };

        private readonly SymmetricJwk _symmetric384Key = new SymmetricJwk
        {
            K = "V4hBa9WfvqqZ4ZWfm2oIoKZaCdy_FEf9cPXMwFSSOivAUMqs931xgQ-fSjTfB9tm"
        };

        private readonly SymmetricJwk _symmetric512Key = new SymmetricJwk
        {
            K = "98TDxdDvd5mKZNFitgMCwH_z7nzKS6sk_vykNTowymsJ4e8eGviJnVWI9i-YLreuBfhHDhis3CY2aKoK1RT6sg"
        };

        private readonly SymmetricJwk _signingKey = SymmetricJwk.GenerateKey(256, SignatureAlgorithm.HmacSha256.Name);

        [Theory]
        [InlineData(ContentEncryptionAlgorithms.Aes128CbcHmacSha256, KeyManagementAlgorithms.Aes128KW)]
        [InlineData(ContentEncryptionAlgorithms.Aes128CbcHmacSha256, KeyManagementAlgorithms.Aes192KW)]
        [InlineData(ContentEncryptionAlgorithms.Aes128CbcHmacSha256, KeyManagementAlgorithms.Aes256KW)]
        [InlineData(ContentEncryptionAlgorithms.Aes128CbcHmacSha256, KeyManagementAlgorithms.Direct)]
        [InlineData(ContentEncryptionAlgorithms.Aes192CbcHmacSha384, KeyManagementAlgorithms.Aes128KW)]
        [InlineData(ContentEncryptionAlgorithms.Aes192CbcHmacSha384, KeyManagementAlgorithms.Aes192KW)]
        [InlineData(ContentEncryptionAlgorithms.Aes192CbcHmacSha384, KeyManagementAlgorithms.Aes256KW)]
        [InlineData(ContentEncryptionAlgorithms.Aes192CbcHmacSha384, KeyManagementAlgorithms.Direct)]
        [InlineData(ContentEncryptionAlgorithms.Aes256CbcHmacSha512, KeyManagementAlgorithms.Aes128KW)]
        [InlineData(ContentEncryptionAlgorithms.Aes256CbcHmacSha512, KeyManagementAlgorithms.Aes192KW)]
        [InlineData(ContentEncryptionAlgorithms.Aes256CbcHmacSha512, KeyManagementAlgorithms.Aes256KW)]
        [InlineData(ContentEncryptionAlgorithms.Aes256CbcHmacSha512, KeyManagementAlgorithms.Direct)]
        public void Encode_Decode(string enc, string alg)
        {
            var writer = new JsonWebTokenWriter();
            var encryptionKey = SelectKey(enc, alg);

            var descriptor = new JweDescriptor
            {
                Key = encryptionKey,
                EncryptionAlgorithm = (EncryptionAlgorithm)enc,
                Algorithm = alg,
                Payload = new JwsDescriptor
                {
                    Key = _signingKey,
                    Algorithm = SignatureAlgorithm.HmacSha256.Name,
                    Subject = "Alice"
                }
            };

            var token = writer.WriteToken(descriptor);

            var reader = new JsonWebTokenReader(encryptionKey);
            var policy = new TokenValidationPolicyBuilder()
                .RequireSignature(_signingKey)
                    .Build();

            var result = reader.TryReadToken(token, policy);
            Assert.Equal(TokenValidationStatus.Success, result.Status);
            Assert.Equal("Alice", result.Token.Subject);
        }

        private SymmetricJwk SelectKey(string enc, string alg)
        {
            switch (alg)
            {
                case KeyManagementAlgorithms.Aes128KW:
                    return _symmetric128Key;
                case KeyManagementAlgorithms.Aes192KW:
                    return _symmetric192Key;
                case KeyManagementAlgorithms.Aes256KW:
                    return _symmetric256Key;
                case KeyManagementAlgorithms.Direct:
                    switch (enc)
                    {
                        case ContentEncryptionAlgorithms.Aes128CbcHmacSha256:
                            return _symmetric256Key;
                        case ContentEncryptionAlgorithms.Aes192CbcHmacSha384:
                            return _symmetric384Key;
                        case ContentEncryptionAlgorithms.Aes256CbcHmacSha512:
                            return _symmetric512Key;
                    }
                    break;
            }

            throw new NotSupportedException();
        }
    }
}