using System;
using System.Buffers;
using System.Collections.Generic;
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

        public TokenValidationResult TryValidate(JsonWebToken jwt)
        {
            if (jwt == null)
            {
                throw new ArgumentNullException(nameof(jwt));
            }

            if (!jwt.HasSignature)
            {
                if (_supportUnsecure && string.Equals(SecurityAlgorithms.None, jwt.SignatureAlgorithm, StringComparison.Ordinal))
                {
                    return TokenValidationResult.Success(jwt);
                }

                return TokenValidationResult.MissingSignature(jwt);
            }

            bool keysTried = false;
            ReadOnlySpan<byte> signatureBytes;
            try
            {
                signatureBytes = jwt.GetSignatureBytes();
            }
            catch (FormatException)
            {
                return TokenValidationResult.MalformedSignature(jwt);
            }

            int length = jwt.Separators[0] + jwt.Separators[1];
            unsafe
            {
#if NETCOREAPP2_1
                var array = ArrayPool<byte>.Shared.Rent(length);
                Span<byte> encodedBytes = array.AsSpan().Slice(0, length);
                try
                {
                    Encoding.UTF8.GetBytes(jwt.RawData.AsSpan().Slice(0, length), encodedBytes);
#else
                    var encodedBytes = Encoding.UTF8.GetBytes(jwt.RawData.Substring(0, length));
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
                    foreach (var key in keys)
                    {
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
                    ArrayPool<byte>.Shared.Return(array);
                }
#endif
            }

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

        private IEnumerable<JsonWebKey> ResolveSigningKey(JsonWebToken jwt)
        {
            var keys = new List<JsonWebKey>();
            var keySet = _keyProvider.GetKeys(jwt);
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
