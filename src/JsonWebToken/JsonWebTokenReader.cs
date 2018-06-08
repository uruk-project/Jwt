using Newtonsoft.Json;
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
            if (encryptionKeyProviders == null)
            {
                throw new ArgumentNullException(nameof(encryptionKeyProviders));
            }

            _encryptionKeyProviders = encryptionKeyProviders.ToArray();
        }

        public JsonWebTokenReader(IKeyProvider encryptionKeyProvider)
            : this(new[] { encryptionKeyProvider ?? throw new ArgumentNullException(nameof(encryptionKeyProvider)) })
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
                JwtHeader header;
                var rawHeader = token.Slice(0, separators[0]);
                try
                {
                    header = GetJsonObject<JwtHeader>(rawHeader);
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
                    JwtPayload payload;
                    try
                    {
                        payload = GetJsonObject<JwtPayload>(rawPayload);
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
                    var enc = header.Enc;
                    if (string.IsNullOrEmpty(enc))
                    {
                        return TokenValidationResult.MissingEncryptionAlgorithm();
                    }

                    var keys = GetContentEncryptionKeys(header, token.Slice(separators[0] + 1, separators[1] - 1));

                    var rawCiphertext = token.Slice(separators[0] + separators[1] + separators[2] + 1, separators[3] - 1);
                    var rawInitializationVector = token.Slice(separators[0] + separators[1] + 1, separators[2] - 1);
                    var rawAuthenticationTag = token.Slice(separators[0] + separators[1] + separators[2] + separators[3] + 1);

                    string decryptedToken = null;
                    JsonWebKey decryptionKey = null;
                    for (int i = 0; i < keys.Count; i++)
                    {
                        decryptionKey = keys[i];
                        if (TryDecryptToken(rawHeader, rawCiphertext, rawInitializationVector, rawAuthenticationTag, enc, decryptionKey, out decryptedToken))
                        {
                            break;
                        }
                    }

                    if (decryptedToken == null)
                    {
                        return TokenValidationResult.DecryptionFailed();
                    }

                    if (!string.Equals(header.Cty, JwtConstants.JwtContentType, StringComparison.Ordinal))
                    {
                        // The decrypted payload is not a nested JWT
                        jwt = new JsonWebToken(header, decryptedToken, separators);
                        jwt.EncryptionKey = decryptionKey;
                        return TokenValidationResult.Success(jwt);
                    }

                    var decryptionResult = TryReadToken(decryptedToken.AsSpan(), validationParameters);
                    if (!decryptionResult.Succedeed)
                    {
                        return decryptionResult;
                    }

                    var decryptedJwt = decryptionResult.Token;
                    jwt = new JsonWebToken(header, decryptedJwt, separators);
                    jwt.EncryptionKey = decryptionKey;
                    return TokenValidationResult.Success(jwt);
                }
                else
                {
                    return TokenValidationResult.MalformedToken();
                }

                return validationParameters.TryValidate(new TokenValidationContext(token, jwt));
            }

            return TokenValidationResult.MalformedToken();
        }

#if NETCOREAPP2_1
        private static T GetJsonObject<T>(ReadOnlySpan<char> data)
        {
            int length = data.Length;
            byte[] utf8ArrayToReturnToPool = null;
            var utf8Buffer = length <= JwtConstants.MaxStackallocBytes
                  ? stackalloc byte[length]
                  : (utf8ArrayToReturnToPool = ArrayPool<byte>.Shared.Rent(length)).AsSpan(0, length);
            try
            {
                Encoding.UTF8.GetBytes(data, utf8Buffer);
                int base64UrlLength = Base64Url.GetArraySizeRequiredToDecode(length);
                byte[] base64UrlArrayToReturnToPool = null;
                var buffer = base64UrlLength <= JwtConstants.MaxStackallocBytes
                  ? stackalloc byte[base64UrlLength]
                  : (base64UrlArrayToReturnToPool = ArrayPool<byte>.Shared.Rent(base64UrlLength)).AsSpan(0, base64UrlLength);
                try
                {
                    Base64Url.Base64UrlDecode(utf8Buffer, buffer, out int byteConsumed, out int bytesWritten);
                    var json = Encoding.UTF8.GetString(buffer);
                    return JsonConvert.DeserializeObject<T>(json);
                }
                finally
                {
                    if (base64UrlArrayToReturnToPool != null)
                    {
                        ArrayPool<byte>.Shared.Return(base64UrlArrayToReturnToPool);
                    }
                }
            }
            finally
            {
                if (utf8ArrayToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(utf8ArrayToReturnToPool);
                }
            }
        }
#else
        private static T GetJsonObject<T>(ReadOnlySpan<char> token)
        {
            int length = token.Length;
            var utf8Buffer = Encoding.UTF8.GetBytes(token.ToString());
            byte[] arrayToReturn = null;
            Span<byte> buffer = length < JwtConstants.MaxStackallocBytes
                ? stackalloc byte[length]
                : (arrayToReturn = ArrayPool<byte>.Shared.Rent(length)).AsSpan(0, length);
            try
            {
                Base64Url.Base64UrlDecode(utf8Buffer.AsSpan().Slice(0, length), buffer, out int headerByteConsumed, out int headerBytesWritten);
                var json = Encoding.UTF8.GetString(buffer.ToArray());
                return JsonConvert.DeserializeObject<T>(json);
            }
            finally
            {
                if (arrayToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturn);
                }
            }
        }
#endif
        private static IReadOnlyList<int> GetSeparators(ReadOnlySpan<char> token)
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
        }

        private bool TryDecryptToken(
            ReadOnlySpan<char> rawHeader,
            ReadOnlySpan<char> rawCiphertext,
            ReadOnlySpan<char> rawInitializationVector,
            ReadOnlySpan<char> rawAuthenticationTag,
            string encryptionAlgorithm,
            JsonWebKey key,
            out string decryptedToken)
        {
            var decryptionProvider = key.CreateAuthenticatedEncryptionProvider(encryptionAlgorithm);
            if (decryptionProvider == null)
            {
                decryptedToken = null;
                return false;
            }

            try
            {
#if NETCOREAPP2_1
                int ciphertextLength = Base64Url.GetArraySizeRequiredToDecode(rawCiphertext.Length);
                int headerLength = rawHeader.Length;
                int initializationVectorLength = Base64Url.GetArraySizeRequiredToDecode(rawInitializationVector.Length);
                int authenticationTagLength = Base64Url.GetArraySizeRequiredToDecode(rawAuthenticationTag.Length);
                int bufferLength = ciphertextLength + headerLength + initializationVectorLength + authenticationTagLength;
                byte[] arrayToReturn = null;
                Span<byte> buffer = bufferLength < JwtConstants.MaxStackallocBytes
                    ? stackalloc byte[bufferLength]
                    : (arrayToReturn = ArrayPool<byte>.Shared.Rent(bufferLength)).AsSpan(0, bufferLength);

                Span<byte> ciphertext = buffer.Slice(0, ciphertextLength);
                Span<byte> header = buffer.Slice(ciphertextLength, headerLength);
                Span<byte> initializationVector = buffer.Slice(ciphertextLength + headerLength, initializationVectorLength);
                Span<byte> authenticationTag = buffer.Slice(ciphertextLength + headerLength + initializationVectorLength, authenticationTagLength);

                byte[] decryptedBytes;
                try
                {
                    int ciphertextBytesWritten = Base64Url.Base64UrlDecode(rawCiphertext, ciphertext);
                    Debug.Assert(ciphertext.Length == ciphertextBytesWritten);

                    int headerBytesWritten = Encoding.ASCII.GetBytes(rawHeader, header);
                    Debug.Assert(header.Length == headerBytesWritten);

                    int ivBytesWritten = Base64Url.Base64UrlDecode(rawInitializationVector, initializationVector);
                    Debug.Assert(initializationVector.Length == ivBytesWritten);

                    int authenticationTagBytesWritten = Base64Url.Base64UrlDecode(rawAuthenticationTag, authenticationTag);
                    Debug.Assert(authenticationTag.Length == authenticationTagBytesWritten);

                    decryptedBytes = decryptionProvider.Decrypt(
                        ciphertext,
                        header,
                        initializationVector,
                        authenticationTag);
                }
                finally
                {
                    if (arrayToReturn != null)
                    {
                        ArrayPool<byte>.Shared.Return(arrayToReturn);
                    }
                }

                if (decryptedBytes == null)
                { 
                    decryptedToken = null;
                    return false;
                }
#else
                var decryptedBytes = decryptionProvider.Decrypt(
                    Base64Url.DecodeBytes(rawCiphertext.ToString()),
                    Encoding.ASCII.GetBytes(rawHeader.ToString()),
                    Base64Url.DecodeBytes(rawInitializationVector.ToString()),
                    Base64Url.DecodeBytes(rawAuthenticationTag.ToString()));
#endif
                decryptedToken = Encoding.UTF8.GetString(decryptedBytes);
                return false;
            }
            finally
            {
                key.ReleaseAuthenticatedEncryptionProvider(decryptionProvider);
            }
        }

        private IList<JsonWebKey> GetContentEncryptionKeys(JwtHeader header, ReadOnlySpan<char> rawEncryptedKey)
        {
            var alg = header.Alg;
            var keys = ResolveDecryptionKey(header);
            if (string.Equals(alg, KeyManagementAlgorithms.Direct, StringComparison.Ordinal))
            {
                return keys;
            }

            Span<byte> encryptedKey = stackalloc byte[Base64Url.GetArraySizeRequiredToDecode(rawEncryptedKey.Length)];
            int bytesWritten = Base64Url.Base64UrlDecode(rawEncryptedKey, encryptedKey);
            Debug.Assert(bytesWritten == encryptedKey.Length);
            var unwrappedKeys = new List<JsonWebKey>();
            for (int i = 0; i < keys.Count; i++)
            {
                var key = keys[i];
                KeyWrapProvider kwp = key.CreateKeyWrapProvider(alg);
                try
                {
                    if (kwp != null)
                    {
                        Span<byte> unwrappedKey = stackalloc byte[kwp.GetKeyUnwrapSize(encryptedKey.Length)];
                        kwp.UnwrapKey(encryptedKey, unwrappedKey, out int keyWrappedBytesWritten);
                        Debug.Assert(keyWrappedBytesWritten == unwrappedKey.Length);
                        unwrappedKeys.Add(SymmetricJwk.FromSpan(unwrappedKey));
                    }
                }
                finally
                {
                    key.ReleaseKeyWrapProvider(kwp);
                }
            }

            return unwrappedKeys;
        }

        private IList<JsonWebKey> ResolveDecryptionKey(JwtHeader header)
        {
            var kid = header.Kid;
            var alg = header.Alg;

            var keys = new List<JsonWebKey>();
            for (int i = 0; i < _encryptionKeyProviders.Count; i++)
            {
                var keySet = _encryptionKeyProviders[i].GetKeys(header);

                for (int j = 0; j < keySet.Count; j++)
                {
                    var key = keySet[j];
                    if ((string.IsNullOrWhiteSpace(key.Use) || string.Equals(key.Use, JsonWebKeyUseNames.Enc, StringComparison.Ordinal)) &&
                        (string.IsNullOrWhiteSpace(key.Alg) || string.Equals(key.Alg, alg, StringComparison.Ordinal)))
                    {
                        keys.Add(key);
                    }
                }
            }

            return keys;
        }
    }
}