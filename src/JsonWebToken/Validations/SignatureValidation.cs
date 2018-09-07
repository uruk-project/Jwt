using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace JsonWebToken.Validations
{
    public class SignatureValidation : IValidation
    {
        private readonly IKeyProvider _keyProvider;
        private readonly bool _supportUnsecure;
        private readonly SignatureAlgorithm _algorithm;

        public SignatureValidation(IKeyProvider keyProvider, bool supportUnsecure, SignatureAlgorithm algorithm)
        {
            _keyProvider = keyProvider;
            _supportUnsecure = supportUnsecure;
            _algorithm = algorithm;
        }

        public TokenValidationResult TryValidate(in TokenValidationContext context)
        {
            var jwt = context.Jwt;
            if (jwt.ContentSegment.Length == 0 && jwt.SignatureSegment.Length == 0)
            {
                // This is not a JWS
                return TokenValidationResult.Success(jwt);
            }

            var token = context.Token;
            if (token.Length <= jwt.ContentSegment.Length + 1)
            {
                if (_supportUnsecure && jwt.SignatureAlgorithm == SignatureAlgorithm.None)
                {
                    return TokenValidationResult.Success(jwt);
                }

                return TokenValidationResult.MissingSignature(jwt);
            }

            int signatureBytesLength;
            try
            {
                signatureBytesLength = Base64Url.GetArraySizeRequiredToDecode(jwt.SignatureSegment.Length);
            }
            catch (FormatException)
            {
                return TokenValidationResult.MalformedSignature();
            }

            Span<byte> signatureBytes = stackalloc byte[signatureBytesLength];
            try
            {
                Base64Url.Base64UrlDecode(token.Slice(jwt.SignatureSegment.Start), signatureBytes, out int byteConsumed, out int bytesWritten);
                Debug.Assert(bytesWritten == signatureBytes.Length);
            }
            catch (FormatException)
            {
                return TokenValidationResult.MalformedSignature();
            }

            bool keysTried = false;
            var encodedBytes = token.Slice(jwt.ContentSegment.Start, jwt.ContentSegment.Length);
            var keys = ResolveSigningKey(jwt);
            for (int i = 0; i < keys.Count; i++)
            {
                JsonWebKey key = keys[i];
                var alg = _algorithm != SignatureAlgorithm.Empty ? _algorithm : (SignatureAlgorithm)key.Alg;
                if (TryValidateSignature(context, encodedBytes, signatureBytes, key, alg))
                {
                    jwt.SigningKey = key;
                    return TokenValidationResult.Success(jwt);
                }

                keysTried = true;
            }

            if (keysTried)
            {
                return TokenValidationResult.InvalidSignature(jwt);
            }

            return TokenValidationResult.KeyNotFound(jwt);
        }

        private static bool TryValidateSignature(in TokenValidationContext context, ReadOnlySpan<byte> encodedBytes, ReadOnlySpan<byte> signature, JsonWebKey key, SignatureAlgorithm algorithm)
        {
            var signatureProvider = context.SignatureFactory.Create(key, algorithm, willCreateSignatures: false);
            if (signatureProvider == null)
            {
                return false;
            }

            return signatureProvider.Verify(encodedBytes, signature);
        }

        private List<JsonWebKey> ResolveSigningKey(JsonWebToken jwt)
        {
            var keys = new List<JsonWebKey>(1);
            var keySet = _keyProvider.GetKeys(jwt.Header);
            if (keySet != null)
            {
                for (int j = 0; j < keySet.Count; j++)
                {
                    var key = keySet[j];
                    if ((string.IsNullOrEmpty(key.Use) || string.Equals(key.Use, JsonWebKeyUseNames.Sig, StringComparison.Ordinal)) &&
                        (string.IsNullOrEmpty(key.Alg) || string.Equals(key.Alg, jwt.Header.Alg, StringComparison.Ordinal)))
                    {
                        keys.Add(key);
                    }
                }
            }

            return keys;
        }
    }
}
