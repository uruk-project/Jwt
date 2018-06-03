using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace JsonWebTokens.Validations
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

        public TokenValidationResult TryValidate(ReadOnlySpan<char> token, JsonWebToken jwt)
        {
            if (jwt == null)
            {
                throw new ArgumentNullException(nameof(jwt));
            }

            if (jwt.Separators.Count != JwtConstants.JwsSeparatorsCount)
            {
                // This is not a JWS
                return TokenValidationResult.Success(jwt);
            }

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
#if NETCOREAPP2_1
                return signatureProvider.Verify(encodedBytes, signature);
#else
                return signatureProvider.Verify(encodedBytes, signature);
#endif
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
                for (int j = 0; j < keySet.Keys.Count; j++)
                {
                    var key = keySet.Keys[j];
                    if ((string.IsNullOrWhiteSpace(key.Use) || string.Equals(key.Use, JsonWebKeyUseNames.Sig, StringComparison.Ordinal)) &&
                        (string.IsNullOrWhiteSpace(key.Alg) || string.Equals(key.Alg, jwt.Header.Alg, StringComparison.Ordinal)) &&
                        (string.Equals(key.Kid, jwt.Header.Kid, StringComparison.Ordinal)))
                    {
                        keys.Add(key);
                    }
                }
            }

            return keys;
        }
    }
}
