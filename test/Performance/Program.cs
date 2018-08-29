using JsonWebToken;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Performance
{
    internal class Program
    {
        private static readonly SymmetricJwk _key = SymmetricJwk.FromBase64Url("U1oK6e4BAR4kKTdyA1OqEFYwX9pIrswuUMNt8qW4z-k");
        private static readonly SymmetricJwk _keyToWrap = SymmetricJwk.FromBase64Url("gXoKEcss-xFuZceE6B3VkEMLw-f0h9tGfyaheF5jqP8");

        private const string Token1 = "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI3NTZFNjk3MTc1NjUyMDY5NjQ2NTZFNzQ2OTY2Njk2NTcyIiwiaXNzIjoiaHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vIiwiaWF0IjoxNTA4MTg0ODQ1LCJhdWQiOiI2MzZDNjk2NTZFNzQ1RjY5NjQiLCJleHAiOjE2MjgxODQ4NDV9.i2JGGP64mggd3WqUj7oX8_FyYh9e_m1MNWI9Q-f-W3g";
        private static readonly JsonWebKey SharedKey = new SymmetricJwk
        {
            Use = "sig",
            Kid = "kid-hs256",
            K = "GdaXeVyiJwKmz5LFhcbcng",
            Alg = SignatureAlgorithm.HmacSha256.Name
        };
        private static readonly JsonWebKey EncryptionKey = SymmetricJwk.GenerateKey(256, KeyManagementAlgorithm.Aes256KW.Name);
        private static readonly JsonWebTokenReader _reader = new JsonWebTokenReader(SharedKey);
        private static readonly JsonWebTokenWriter _writer = new JsonWebTokenWriter();
        private static readonly TokenValidationPolicy policy = new TokenValidationPolicyBuilder()
                    .RequireSignature(SharedKey)
                    .Build();

        private static void Main(string[] args)
        {
            Console.WriteLine("Starting...");
            int size = System.Runtime.InteropServices.Marshal.SizeOf<SignatureAlgorithm>();
            //for (int i = 0; i < 5000000; i++)
            //{
            //    var result = _reader.TryReadToken(Token1, parameters);
            //}

            //foreach (var token in new [] { "enc-small" })
            //{
            //    var result = _reader.TryReadToken(Tokens.ValidTokens[token].AsSpan(), new TokenValidationBuilder().RequireSignature(Tokens.SigningKey).Build());

            //}
            var expires = new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc);
            var issuedAt = new DateTime(2017, 7, 14, 4, 40, 0, DateTimeKind.Utc);
            var issuer = "https://idp.example.com/";
            var audience = "636C69656E745F6964";
            var jws = new JwsDescriptor()
            {
                IssuedAt = issuedAt,
                ExpirationTime = expires,
                Issuer = issuer,
                Audience = audience,
                Key = SharedKey
            };
            var jwe = new JweDescriptor
            {
                Key = EncryptionKey,
                EncryptionAlgorithm = EncryptionAlgorithm.Aes128CbcHmacSha256,
                Payload = jws
            };
            //var jwt = _writer.WriteToken(jwe);

            //Parallel.For(0, 10, _ =>
            //{
            //for (int i = 0; i < 1000000; i++)
            //{
            //    var result = _reader.TryReadToken(jwt.AsSpan(), policy);
            ////}
            _writer.EnableHeaderCaching = false;
            while (true)
            {
                var jwt = _writer.WriteToken(jws);
            }

            //var keyData = new byte[32];
            //RandomNumberGenerator.Fill(keyData);
            //var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            //var key = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(keyData);
            //key.CryptoProviderFactory.CacheSignatureProviders = true;
            //Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
            //var signingKey = new Microsoft.IdentityModel.Tokens.SigningCredentials(key, "HS256");
            //handler.CreateEncodedJwt(new Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor());
            //while (true)
            //{
            //    handler.CreateJwtSecurityToken(issuer: "me", signingCredentials: signingKey);
            //}
            ////});

            //var kwp = new AesKeyWrapProvider(_key, CryptographicAlgorithm.Aes128CbcHmacSha256, SignatureAlgorithm.Aes256KW);
            //byte[] wrappedKey = new byte[kwp.GetKeyWrapSize()];
            //var unwrappedKey = new byte[kwp.GetKeyUnwrapSize(wrappedKey.Length)];
            //while (true)
            //{
            //    var wrapped = kwp.TryWrapKey(_keyToWrap, null, wrappedKey, out var cek, out var bytesWritten);
            //    var unwrapped = kwp.TryUnwrapKey(wrappedKey, unwrappedKey, null, out int keyWrappedBytesWritten);
            //}
        }
    }

    public readonly struct SignatureAlgorithm : IEquatable<SignatureAlgorithm>
    {
        public static readonly SignatureAlgorithm Empty = default;

        // signature algorithms
        public static readonly SignatureAlgorithm None = new SignatureAlgorithm(id: -1, SignatureAlgorithms.None, AlgorithmCategory.None, requiredKeySizeInBits: 0, new HashAlgorithmName());

        public static readonly SignatureAlgorithm HmacSha256 = new SignatureAlgorithm(id: 11, SignatureAlgorithms.HmacSha256, AlgorithmCategory.Symmetric, requiredKeySizeInBits: 128/*?*/, HashAlgorithmName.SHA256);
        public static readonly SignatureAlgorithm HmacSha384 = new SignatureAlgorithm(id: 12, SignatureAlgorithms.HmacSha384, AlgorithmCategory.Symmetric, requiredKeySizeInBits: 192/*?*/, HashAlgorithmName.SHA384);
        public static readonly SignatureAlgorithm HmacSha512 = new SignatureAlgorithm(id: 13, SignatureAlgorithms.HmacSha512, AlgorithmCategory.Symmetric, requiredKeySizeInBits: 256/*?*/, HashAlgorithmName.SHA512);

        public static readonly SignatureAlgorithm RsaSha256 = new SignatureAlgorithm(id: 21, SignatureAlgorithms.RsaSha256, AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048/*?*/, HashAlgorithmName.SHA256);
        public static readonly SignatureAlgorithm RsaSha384 = new SignatureAlgorithm(id: 22, SignatureAlgorithms.RsaSha384, AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048/*?*/, HashAlgorithmName.SHA384);
        public static readonly SignatureAlgorithm RsaSha512 = new SignatureAlgorithm(id: 23, SignatureAlgorithms.RsaSha512, AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048/*?*/, HashAlgorithmName.SHA512);

        public static readonly SignatureAlgorithm EcdsaSha256 = new SignatureAlgorithm(id: 31, SignatureAlgorithms.EcdsaSha256, AlgorithmCategory.EllipticCurve, requiredKeySizeInBits: 256, HashAlgorithmName.SHA256);
        public static readonly SignatureAlgorithm EcdsaSha384 = new SignatureAlgorithm(id: 32, SignatureAlgorithms.EcdsaSha384, AlgorithmCategory.EllipticCurve, requiredKeySizeInBits: 384, HashAlgorithmName.SHA384);
        public static readonly SignatureAlgorithm EcdsaSha512 = new SignatureAlgorithm(id: 33, SignatureAlgorithms.EcdsaSha512, AlgorithmCategory.EllipticCurve, requiredKeySizeInBits: 521, HashAlgorithmName.SHA512);

        public static readonly SignatureAlgorithm RsaSsaPssSha256 = new SignatureAlgorithm(id: 40, SignatureAlgorithms.RsaSsaPssSha256, AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048, HashAlgorithmName.SHA256);
        public static readonly SignatureAlgorithm RsaSsaPssSha384 = new SignatureAlgorithm(id: 41, SignatureAlgorithms.RsaSsaPssSha384, AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048, HashAlgorithmName.SHA384);
        public static readonly SignatureAlgorithm RsaSsaPssSha512 = new SignatureAlgorithm(id: 42, SignatureAlgorithms.RsaSsaPssSha512, AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048, HashAlgorithmName.SHA512);

        public static readonly IDictionary<string, SignatureAlgorithm> AdditionalAlgorithms = new Dictionary<string, SignatureAlgorithm>();

        private readonly sbyte _id;

        public readonly AlgorithmCategory Category;
        public readonly ushort RequiredKeySizeInBits;
        public readonly string Name;
        public readonly HashAlgorithmName HashAlgorithm;

        private SignatureAlgorithm(sbyte id, string name, AlgorithmCategory keyType, ushort requiredKeySizeInBits, HashAlgorithmName hashAlgorithm)
        {
            _id = id;
            Name = name;
            Category = keyType;
            RequiredKeySizeInBits = requiredKeySizeInBits;
            HashAlgorithm = hashAlgorithm;
        }

        public override bool Equals(object obj)
        {
            if (obj is SignatureAlgorithm alg)
            {
                return Equals(alg);
            }

            return false;
        }

        public bool Equals(SignatureAlgorithm other)
        {
            //if (other is null)
            //{
            //    return false;
            //}

            return _id == other._id;
        }

        public override int GetHashCode()
        {
            return _id.GetHashCode();
        }

        public static bool operator ==(SignatureAlgorithm x, SignatureAlgorithm y)
        {
            //if (x is null && y is null)
            //{
            //    return true;
            //}

            //if (x is null)
            //{
            //    return false;
            //}

            //if (y is null)
            //{
            //    return false;
            //}

            return x._id == y._id;
        }

        public static bool operator !=(SignatureAlgorithm x, SignatureAlgorithm y)
        {
            //if (x is null && y is null)
            //{
            //    return false;
            //}

            //if (x is null)
            //{
            //    return true;
            //}

            //if (y is null)
            //{
            //    return true;
            //}

            return x._id != y._id;
        }

        public static implicit operator string(SignatureAlgorithm value)
        {
            return value.Name;
        }

        public static implicit operator SignatureAlgorithm(string value)
        {
            switch (value)
            {
                case SignatureAlgorithms.EcdsaSha256:
                    return EcdsaSha256;
                case SignatureAlgorithms.EcdsaSha384:
                    return EcdsaSha384;
                case SignatureAlgorithms.EcdsaSha512:
                    return EcdsaSha512;

                case SignatureAlgorithms.HmacSha256:
                    return HmacSha256;
                case SignatureAlgorithms.HmacSha384:
                    return HmacSha384;
                case SignatureAlgorithms.HmacSha512:
                    return HmacSha512;

                case SignatureAlgorithms.RsaSha256:
                    return RsaSha256;
                case SignatureAlgorithms.RsaSha384:
                    return RsaSha384;
                case SignatureAlgorithms.RsaSha512:
                    return RsaSha512;

                case SignatureAlgorithms.RsaSsaPssSha256:
                    return RsaSsaPssSha256;
                case SignatureAlgorithms.RsaSsaPssSha384:
                    return RsaSsaPssSha384;
                case SignatureAlgorithms.RsaSsaPssSha512:
                    return RsaSsaPssSha512;

                case SignatureAlgorithms.None:
                    return None;

                case null:
                case "":
                    return Empty;
            }

            if (AdditionalAlgorithms.TryGetValue(value, out var algorithm))
            {
                return algorithm;
            }

            throw new NotSupportedException(ErrorMessages.FormatInvariant("", value));
        }


        public static implicit operator long(SignatureAlgorithm value)
        {
            return value._id;
        }

        public override string ToString()
        {
            return Name;
        }
    }
}

