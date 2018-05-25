using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace JsonWebToken
{
    public class JsonWebTokenReader
    {
        private readonly IList<IKeyProvider> _encryptionKeyProviders;

        public JsonWebTokenReader(IEnumerable<IKeyProvider> encryptionKeyProviders)
        {
            _encryptionKeyProviders = encryptionKeyProviders.ToArray();
        }

        public JsonWebTokenReader(IKeyProvider encryptionKeyProvider)
            : this(new[] { encryptionKeyProvider })
        {
        }

        public JsonWebTokenReader(JsonWebKeySet encryptionKeys)
            : this(new StaticKeyProvider(encryptionKeys))
        {
        }

        public JsonWebTokenReader(JsonWebKey encryptionKey)
            : this(new JsonWebKeySet(encryptionKey))
        {
        }

        public JsonWebTokenReader()
        {
            _encryptionKeyProviders = new IKeyProvider[0];
        }

        /// <summary>
        /// Reads and validates a 'JSON Web Token' (JWT) encoded as a JWS or JWE in Compact Serialized Format.
        /// </summary>
        /// <param name="token">the JWT encoded as JWE or JWS</param>
        /// <param name="validationParameters">Contains validation parameters for the <see cref="JsonWebToken"/>.</param>
        /// <param name="validatedToken">The <see cref="JsonWebToken"/> that was validated.</param>
        public TokenValidationResult TryReadToken(ReadOnlySpan<char> token, TokenValidationParameters validationParameters)
        {
            if (validationParameters == null)
            {
                throw new ArgumentNullException(nameof(validationParameters));
            }

            if (token == null || token.Length == 0)
            {
                return TokenValidationResult.MalformedToken();
            }

            if (token.Length > validationParameters.MaximumTokenSizeInBytes)
            {
                return TokenValidationResult.MalformedToken();
            }

            var separators = GetSeparators(token);
            if (separators.Count == JwtConstants.JwsSeparatorsCount || separators.Count == JwtConstants.JweSeparatorsCount)
            {
                JObject header;
                var rawHeader = token.Slice(0, separators[0]);
                try
                {
                    header = GetJsonObject(rawHeader);
                }
                catch (FormatException)
                {
                    return TokenValidationResult.MalformedToken();
                }
                catch (JsonReaderException)
                {
                    return TokenValidationResult.MalformedToken();
                }

                JsonWebToken jwt;

                if (separators.Count == JwtConstants.JwsSeparatorsCount)
                {
                    var rawPayload = token.Slice(separators[0] + 1, separators[1] - 1);
                    JObject payload;
                    try
                    {
                        payload = GetJsonObject(rawPayload);
                    }
                    catch (FormatException)
                    {
                        return TokenValidationResult.MalformedToken();
                    }
                    catch (JsonReaderException)
                    {
                        return TokenValidationResult.MalformedToken();
                    }

                    jwt = new JsonWebToken(header, payload, separators);
                }
                else if (separators.Count == JwtConstants.JweSeparatorsCount)
                {
                    var enc = header.Value<string>(JwtHeaderParameterNames.Enc);
                    if (string.IsNullOrEmpty(enc))
                    {
                        return TokenValidationResult.MissingEncryptionAlgorithm();
                    }

                    var keys = GetContentEncryptionKeys(header, token.Slice(separators[0] + 1, separators[1] - 1));

                    var rawCiphertext = token.Slice(separators[0] + separators[1] + separators[2] + 1, separators[3] - 1);
                    var rawInitializationVector = token.Slice(separators[0] + separators[1] + 1, separators[2] - 1);
                    var rawAuthenticationTag = token.Slice(separators[0] + separators[1] + separators[2] + separators[3] + 1);

                    string decryptedToken = null;
                    for (int i = 0; i < keys.Count; i++)
                    {
                        decryptedToken = DecryptToken(rawHeader, rawCiphertext, rawInitializationVector, rawAuthenticationTag, enc, keys[i]);
                        if (decryptedToken != null)
                        {
                            break;
                        }
                    }

                    if (decryptedToken == null)
                    {
                        return TokenValidationResult.DecryptionFailed();
                    }

                    if (!string.Equals(header.Value<string>(JwtHeaderParameterNames.Cty), JwtConstants.JwtContentType, StringComparison.Ordinal))
                    {
                        // The decrypted payload is not a nested JWT
                        jwt = new JsonWebToken(header, decryptedToken, separators);
                        return TokenValidationResult.Success(jwt);
                    }

                    var decryptionResult = TryReadToken(decryptedToken.AsSpan(), validationParameters);
                    if (!decryptionResult.Succedeed)
                    {
                        return decryptionResult;
                    }

                    var decryptedJwt = decryptionResult.Token;
                    jwt = new JsonWebToken(header, decryptedJwt, separators);
                    return TokenValidationResult.Success(jwt);
                }
                else
                {
                    return TokenValidationResult.MalformedToken();
                }

                return validationParameters.TryValidate(token, jwt);
            }

            return TokenValidationResult.MalformedToken();
        }

#if NETCOREAPP2_1
        private static JObject GetJsonObject(ReadOnlySpan<char> data)
        {
            int length = data.Length;

            if (length > 1024 * 1024)
            {
                unsafe
                {
                    var utf8Buffer = ArrayPool<byte>.Shared.Rent(length);
                    try
                    {
                        Encoding.UTF8.GetBytes(data, utf8Buffer);
                        var buffer = ArrayPool<byte>.Shared.Rent(Base64Url.GetArraySizeRequiredToDecode(length));
                        try
                        {
                            Base64Url.Base64UrlDecode(utf8Buffer, buffer, out int byteConsumed, out int bytesWritten);
                            var json = Encoding.UTF8.GetString(buffer);


                            return JObject.Parse(json);
                        }
                        finally
                        {
                            ArrayPool<byte>.Shared.Return(buffer);
                        }
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(utf8Buffer);
                    }
                }
            }
            else
            {
                unsafe
                {
                    Span<byte> utf8Buffer = stackalloc byte[length];
                    Encoding.UTF8.GetBytes(data, utf8Buffer);
                    Span<byte> buffer = stackalloc byte[Base64Url.GetArraySizeRequiredToDecode(length)];
                    Base64Url.Base64UrlDecode(utf8Buffer, buffer, out int byteConsumed, out int bytesWritten);
                    Debug.Assert(utf8Buffer.Length == byteConsumed);
                    Debug.Assert(buffer.Length == bytesWritten);
                    var json = Encoding.UTF8.GetString(buffer);
                    return JObject.Parse(json);
                }
            }

        }
#else
        private static JObject GetJsonObject(ReadOnlySpan<char> token)
        {
            int length = token.Length;
            var headerUtf8Buffer = Encoding.UTF8.GetBytes(token.ToString());
            var headerBuffer = ArrayPool<byte>.Shared.Rent(Base64Url.GetArraySizeRequiredToDecode(length));
            try
            {
                Base64Url.Base64UrlDecode(headerUtf8Buffer.AsSpan().Slice(0, length), headerBuffer, out int headerByteConsumed, out int headerBytesWritten);
                var json = Encoding.UTF8.GetString(headerBuffer);

                return JObject.Parse(json);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(headerBuffer);
            }
        }
#endif
        private static IList<int> GetSeparators(ReadOnlySpan<char> token)
        {
            int next = 0;
            int current = 0;
            int i = 0;
            List<int> separators = new List<int>();

            while ((next = token.IndexOf('.')) != -1)
            {
                separators.Add(next + (i == 0 ? 0 : 1));
                if (separators.Count > JwtConstants.MaxJwtSeparatorsCount)
                {
                    break;
                }

                i++;
                current = next;
                token = token.Slice(next + 1);
            }

            return separators;
            //int next = 0;
            //int current = 0;
            //int i = 0;
            //List<int> separators = new List<int>();

            //while ((next = new string(token.ToArray()).IndexOf('.', next + 1)) != -1)
            //{
            //    separators.Add(next - current);
            //    if (separators.Count > JwtConstants.MaxJwtSeparatorsCount)
            //    {
            //        break;
            //    }

            //    i++;
            //    current = next;
            //}

            //return separators;
        }

        private string DecryptToken(
            ReadOnlySpan<char> rawHeader,
            ReadOnlySpan<char> rawCiphertext,
            ReadOnlySpan<char> rawInitializationVector,
            ReadOnlySpan<char> rawAuthenticationTag,
            string encryptionAlgorithm,
            JsonWebKey key)
        {
            var decryptionProvider = key.CreateAuthenticatedEncryptionProvider(encryptionAlgorithm);
            if (decryptionProvider == null)
            {
                return null;
            }

            try
            {
#if NETCOREAPP2_1
                Span<byte> ciphertext = stackalloc byte[Base64Url.GetArraySizeRequiredToDecode(rawCiphertext.Length)];
                int ciphertextBytesWritten = Base64Url.Base64UrlDecode(rawCiphertext, ciphertext);
                Debug.Assert(ciphertext.Length == ciphertextBytesWritten);

                Span<byte> header = stackalloc byte[rawHeader.Length];
                int headerBytesWritten = Encoding.ASCII.GetBytes(rawHeader, header);
                Debug.Assert(header.Length == headerBytesWritten);

                Span<byte> initializationVector = stackalloc byte[Base64Url.GetArraySizeRequiredToDecode(rawInitializationVector.Length)];
                int ivBytesWritten = Base64Url.Base64UrlDecode(rawInitializationVector, initializationVector);
                Debug.Assert(initializationVector.Length == ivBytesWritten);

                Span<byte> authenticationTag = stackalloc byte[Base64Url.GetArraySizeRequiredToDecode(rawAuthenticationTag.Length)];
                int authenticationTagBytesWritten = Base64Url.Base64UrlDecode(rawAuthenticationTag, authenticationTag);
                Debug.Assert(authenticationTag.Length == authenticationTagBytesWritten);

                var decryptedToken = decryptionProvider.Decrypt(
                    ciphertext.Slice(0, ciphertextBytesWritten),
                    header.Slice(0, headerBytesWritten),
                    initializationVector.Slice(0, ivBytesWritten),
                    authenticationTag.Slice(0, authenticationTagBytesWritten));
                if (decryptedToken == null)
                {
                    return null;
                }
#else
                var decryptedToken = decryptionProvider.Decrypt(
                    Base64Url.DecodeBytes(rawCiphertext.ToString()),
                    Encoding.ASCII.GetBytes(rawHeader.ToString()),
                    Base64Url.DecodeBytes(rawInitializationVector.ToString()),
                    Base64Url.DecodeBytes(rawAuthenticationTag.ToString()));
#endif
                return Encoding.UTF8.GetString(decryptedToken);
            }
            finally
            {
                key.ReleaseAuthenticatedEncryptionProvider(decryptionProvider);
            }
        }

        private IList<JsonWebKey> GetContentEncryptionKeys(JObject header, ReadOnlySpan<char> rawEncryptedKey)
        {
            var alg = header.Value<string>("alg");
            var keys = ResolveDecryptionKey(header);
            if (string.Equals(alg, SecurityAlgorithms.Direct, StringComparison.Ordinal))
            {
                return keys;
            }

            var unwrappedKeys = new List<JsonWebKey>();
            for (int i = 0; i < keys.Count; i++)
            {
                var key = keys[i];
                KeyWrapProvider kwp = key.CreateKeyWrapProvider(alg);
                try
                {
                    if (kwp != null)
                    {
                        Span<byte> encryptedKey = stackalloc byte[Base64Url.GetArraySizeRequiredToDecode(rawEncryptedKey.Length)];
                        int bytesWritten = Base64Url.Base64UrlDecode(rawEncryptedKey, encryptedKey);
                        var unwrappedKey = kwp.UnwrapKey(encryptedKey.Slice(0, bytesWritten).ToArray());
                        unwrappedKeys.Add(SymmetricJwk.FromByteArray(unwrappedKey));
                    }
                }
                finally
                {
                    key.ReleaseKeyWrapProvider(kwp);
                }
            }

            return unwrappedKeys;
        }

        private IList<JsonWebKey> ResolveDecryptionKey(JObject header)
        {
            var kid = header.Value<string>("kid");
            var alg = header.Value<string>("alg");

            var keys = new List<JsonWebKey>();
            for (int i = 0; i < _encryptionKeyProviders.Count; i++)
            {
                var keySet = _encryptionKeyProviders[i].GetKeys(header);

                for (int j = 0; j < keySet.Keys.Count; j++)
                {
                    var key = keySet.Keys[j];
                    if ((string.IsNullOrWhiteSpace(key.Use) || string.Equals(key.Use, JsonWebKeyUseNames.Enc, StringComparison.Ordinal)) &&
                        (string.IsNullOrWhiteSpace(key.Alg) || string.Equals(key.Alg, alg, StringComparison.Ordinal)) &&
                        (string.Equals(key.Kid, kid, StringComparison.Ordinal)))
                    {
                        keys.Add(key);
                    }
                }
            }

            return keys;
        }
    }
}