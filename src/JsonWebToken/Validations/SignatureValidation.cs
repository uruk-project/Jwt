using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace JsonWebToken.Validations
{
    public class SignatureValidation : IValidation
    {
        private readonly IKeyProvider _keyProvider;
        private readonly bool _supportUnsecure;

        public SignatureValidation(IKeyProvider keyProvider, bool supportUnsecure)
        {
            _keyProvider = keyProvider;
            _supportUnsecure = supportUnsecure;
        }

        public TokenValidationResult TryValidate(TokenValidationContext context)
        {
            var jwt = context.Jwt;
            if (jwt.Separators.Count != JwtConstants.JwsSeparatorsCount)
            {
                // This is not a JWS
                return TokenValidationResult.Success(jwt);
            }

            var token = context.Token;
            if (token.Length <= jwt.Separators[0] + jwt.Separators[1] + 1)
            {
                if (_supportUnsecure && string.Equals(SignatureAlgorithms.None, jwt.SignatureAlgorithm, StringComparison.Ordinal))
                {
                    return TokenValidationResult.Success(jwt);
                }

                return TokenValidationResult.MissingSignature(jwt);
            }

            int signatureLength = token.Length - (jwt.Separators[0] + jwt.Separators[1] + 1);
            int signatureBytesLength;
            try
            {
                signatureBytesLength = Base64Url.GetArraySizeRequiredToDecode(signatureLength);
            }
            catch (FormatException)
            {
                return TokenValidationResult.MalformedSignature();
            }

            Span<byte> signatureBytes = stackalloc byte[signatureBytesLength];
            try
            {
                Base64Url.Base64UrlDecode(token.Slice(jwt.Separators[0] + jwt.Separators[1] + 1), signatureBytes, out int byteConsumed, out int bytesWritten);
                Debug.Assert(bytesWritten == signatureBytes.Length);
            }
            catch (FormatException)
            {
                return TokenValidationResult.MalformedSignature();
            }

            bool keysTried = false;
            int length = jwt.Separators[0] + jwt.Separators[1];
#if NETCOREAPP2_1
            byte[] arrayToReturnToPool = null;
            Span<byte> encodedBytes = length <= JwtConstants.MaxStackallocBytes
                                      ? stackalloc byte[length]
                                      : (arrayToReturnToPool = ArrayPool<byte>.Shared.Rent(length)).AsSpan(0, length);
            try
            {
                Encoding.UTF8.GetBytes(token.Slice(0, length), encodedBytes);
#else
                var encodedBytes = Encoding.UTF8.GetBytes(token.Slice(0, length).ToString());
#endif
                JwtHeader header;
                try
                {
                    header = jwt.Header;
                }
                catch (FormatException)
                {
                    return TokenValidationResult.MalformedToken();
                }

                var keys = ResolveSigningKey(jwt);
                for (int i = 0; i < keys.Count; i++)
                {
                    JsonWebKey key = keys[i];
                    if (TryValidateSignature(encodedBytes, signatureBytes, key, key.Alg))
                    {
                        jwt.Header.SigningKey = key;
                        return TokenValidationResult.Success(jwt);
                    }

                    keysTried = true;

                }
#if NETCOREAPP2_1
            }
            finally
            {
                if (arrayToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturnToPool);
                }
            }
#endif

            if (keysTried)
            {
                return TokenValidationResult.InvalidSignature(jwt);
            }

            return TokenValidationResult.KeyNotFound(jwt);
        }

        private bool TryValidateSignature(ReadOnlySpan<byte> encodedBytes, ReadOnlySpan<byte> signature, JsonWebKey key, string algorithm)
        {
            var signatureProvider = key.CreateSignatureProvider(algorithm, false);
            if (signatureProvider == null)
            {
                return false;
            }

            try
            {
                return signatureProvider.Verify(encodedBytes, signature);
            }
            finally
            {
                key.ReleaseSignatureProvider(signatureProvider);
            }
        }

        private IList<JsonWebKey> ResolveSigningKey(JsonWebToken jwt)
        {
            var keys = new List<JsonWebKey>();
            var keySet = _keyProvider.GetKeys(jwt.Header);
            if (keySet != null)
            {
                for (int j = 0; j < keySet.Count; j++)
                {
                    var key = keySet[j];
                    if ((string.IsNullOrWhiteSpace(key.Use) || string.Equals(key.Use, JsonWebKeyUseNames.Sig, StringComparison.Ordinal)) &&
                        (string.IsNullOrWhiteSpace(key.Alg) || string.Equals(key.Alg, jwt.Header.Alg, StringComparison.Ordinal)))
                    {
                        keys.Add(key);
                    }
                }
            }

            return keys;
        }
    }
}
