using Newtonsoft.Json;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;

namespace JsonWebToken
{
    public class JsonWebTokenReader
    {
        private const byte dot = 0x2E;
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

#if NETCOREAPP2_1
            int length = token.Length;
            byte[] utf8ArrayToReturnToPool = null;
            var utf8Buffer = length <= Constants.MaxStackallocBytes
                  ? stackalloc byte[length]
                  : (utf8ArrayToReturnToPool = ArrayPool<byte>.Shared.Rent(length)).AsSpan(0, length);
            try
            {
                Encoding.UTF8.GetBytes(token, utf8Buffer);
                return TryReadToken(utf8Buffer, validationParameters);
            }
            finally
            {
                if (utf8ArrayToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(utf8ArrayToReturnToPool);
                }
            }
#else
            var utf8Buffer = Encoding.UTF8.GetBytes(token.ToArray()).AsSpan();
            return TryReadToken(utf8Buffer, validationParameters);
#endif
        }

        private TokenValidationResult TryReadToken(ReadOnlySpan<byte> utf8Buffer, TokenValidationParameters validationParameters)
        {
            var separators = GetSeparators(utf8Buffer);
            if (separators.Count == Constants.JwsSeparatorsCount || separators.Count == Constants.JweSeparatorsCount)
            {
                JwtHeader header;
                var rawHeader = utf8Buffer.Slice(0, separators[0]);
                try
                {
                    var hash = ComputeHash(rawHeader);
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
                if (separators.Count == Constants.JwsSeparatorsCount)
                {
                    var rawPayload = utf8Buffer.Slice(separators[0] + 1, separators[1] - 1);
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
                else if (separators.Count == Constants.JweSeparatorsCount)
                {
                    var enc = header.Enc;
                    if (string.IsNullOrEmpty(enc))
                    {
                        return TokenValidationResult.MissingEncryptionAlgorithm();
                    }

                    var keys = GetContentEncryptionKeys(header, utf8Buffer.Slice(separators[0] + 1, separators[1] - 1));

                    var rawCiphertext = utf8Buffer.Slice(separators[0] + separators[1] + separators[2] + 1, separators[3] - 1);
                    var rawInitializationVector = utf8Buffer.Slice(separators[0] + separators[1] + 1, separators[2] - 1);
                    var rawAuthenticationTag = utf8Buffer.Slice(separators[0] + separators[1] + separators[2] + separators[3] + 1);

                    var compressionAlgorithm = header.Zip;

                    byte[] decryptedBytes = null;
                    JsonWebKey decryptionKey = null;
                    for (int i = 0; i < keys.Count; i++)
                    {
                        decryptionKey = keys[i];
                        if (TryDecryptToken(rawHeader, rawCiphertext, rawInitializationVector, rawAuthenticationTag, enc, compressionAlgorithm, decryptionKey, out decryptedBytes))
                        {
                            break;
                        }
                    }

                    if (decryptedBytes == null)
                    {
                        return TokenValidationResult.DecryptionFailed();
                    }

                    if (!string.Equals(header.Cty, HeaderParameters.CtyValues.Jwt, StringComparison.Ordinal))
                    {
                        // The decrypted payload is not a nested JWT
                        jwt = new JsonWebToken(header, decryptedBytes, separators);
                        jwt.EncryptionKey = decryptionKey;
                        return TokenValidationResult.Success(jwt);
                    }

                    var decryptionResult = TryReadToken(decryptedBytes, validationParameters);
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

                return validationParameters.TryValidate(new TokenValidationContext(utf8Buffer, jwt));
            }

            return TokenValidationResult.MalformedToken();
        }

        private static T GetJsonObject<T>(ReadOnlySpan<byte> data)
        {
            int base64UrlLength = Base64Url.GetArraySizeRequiredToDecode(data.Length);
            byte[] base64UrlArrayToReturnToPool = null;
            var buffer = base64UrlLength <= Constants.MaxStackallocBytes
              ? stackalloc byte[base64UrlLength]
              : (base64UrlArrayToReturnToPool = ArrayPool<byte>.Shared.Rent(base64UrlLength)).AsSpan(0, base64UrlLength);
            try
            {
                Base64Url.Base64UrlDecode(data, buffer, out int byteConsumed, out int bytesWritten);
#if NETCOREAPP2_1
                var json = Encoding.UTF8.GetString(buffer);
#else
                var json = Encoding.UTF8.GetString(buffer.ToArray());
#endif
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

        private static IReadOnlyList<int> GetSeparators(ReadOnlySpan<byte> token)
        {
            int next = 0;
            int current = 0;
            int i = 0;
            List<int> separators = new List<int>();

            while ((next = token.IndexOf(dot)) != -1)
            {
                separators.Add(next + (i == 0 ? 0 : 1));
                if (separators.Count > Constants.MaxJwtSeparatorsCount)
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
            ReadOnlySpan<byte> rawHeader,
            ReadOnlySpan<byte> rawCiphertext,
            ReadOnlySpan<byte> rawInitializationVector,
            ReadOnlySpan<byte> rawAuthenticationTag,
            string encryptionAlgorithm,
            string compressionAlgorithm,
            JsonWebKey key,
            out byte[] decryptedBytes)
        {
            var decryptionProvider = key.CreateAuthenticatedEncryptionProvider(encryptionAlgorithm);
            if (decryptionProvider == null)
            {
                decryptedBytes = null;
                return false;
            }

            CompressionProvider compressionProvider = null;
            if (!string.IsNullOrEmpty(compressionAlgorithm))
            {
                compressionProvider = CompressionProvider.CreateCompressionProvider(compressionAlgorithm);
                if (compressionProvider == null)
                {
                    decryptedBytes = null;
                    return false;
                }
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
                char[] headerArrayToReturn = null;
                byte[] uncompressedBytesToReturn = null;
                Span<byte> buffer = bufferLength < Constants.MaxStackallocBytes
                    ? stackalloc byte[bufferLength]
                    : (arrayToReturn = ArrayPool<byte>.Shared.Rent(bufferLength)).AsSpan(0, bufferLength);

                Span<char> utf8Header = headerLength < Constants.MaxStackallocBytes
                    ? stackalloc char[headerLength]
                    : (headerArrayToReturn = ArrayPool<char>.Shared.Rent(headerLength)).AsSpan(0, headerLength);

                Span<byte> ciphertext = buffer.Slice(0, ciphertextLength);
                Span<byte> header = buffer.Slice(ciphertextLength, headerLength);
                Span<byte> initializationVector = buffer.Slice(ciphertextLength + headerLength, initializationVectorLength);
                Span<byte> authenticationTag = buffer.Slice(ciphertextLength + headerLength + initializationVectorLength, authenticationTagLength);
                try
                {
                    Base64Url.Base64UrlDecode(rawCiphertext, ciphertext, out int ciphertextBytesConsumed, out int ciphertextBytesWritten);
                    Debug.Assert(ciphertext.Length == ciphertextBytesWritten);
                    
                    Encoding.UTF8.GetChars(rawHeader, utf8Header);
                    Encoding.ASCII.GetBytes(utf8Header, header);

                    Base64Url.Base64UrlDecode(rawInitializationVector, initializationVector, out int ivBytesConsumed, out int ivBytesWritten);
                    Debug.Assert(initializationVector.Length == ivBytesWritten);

                    Base64Url.Base64UrlDecode(rawAuthenticationTag, authenticationTag, out int authenticationTagBytesConsumed, out int authenticationTagBytesWritten);
                    Debug.Assert(authenticationTag.Length == authenticationTagBytesWritten);

                    decryptedBytes = decryptionProvider.Decrypt(
                        ciphertext,
                        header,
                        initializationVector,
                        authenticationTag);

                    if (compressionAlgorithm != null)
                    {
                        decryptedBytes = compressionProvider.Decompress(decryptedBytes).ToArray();
                    }
                }
                finally
                {
                    if (arrayToReturn != null)
                    {
                        ArrayPool<byte>.Shared.Return(arrayToReturn);
                    }
                    if (headerArrayToReturn != null)
                    {
                        ArrayPool<char>.Shared.Return(headerArrayToReturn);
                    }
                    if (uncompressedBytesToReturn != null)
                    {
                        ArrayPool<byte>.Shared.Return(uncompressedBytesToReturn);
                    }
                }
#else
                decryptedBytes = decryptionProvider.Decrypt(
                    Base64Url.DecodeBytes(rawCiphertext.ToString()),
                    Encoding.ASCII.GetBytes(rawHeader.ToString()),
                    Base64Url.DecodeBytes(rawInitializationVector.ToString()),
                    Base64Url.DecodeBytes(rawAuthenticationTag.ToString()));
#endif
                return decryptedBytes != null;
            }
            finally
            {
                key.ReleaseAuthenticatedEncryptionProvider(decryptionProvider);
            }
        }

        private IList<JsonWebKey> GetContentEncryptionKeys(JwtHeader header, ReadOnlySpan<byte> rawEncryptedKey)
        {
            var alg = header.Alg;
            var keys = ResolveDecryptionKey(header);
            if (string.Equals(alg, KeyManagementAlgorithms.Direct, StringComparison.Ordinal))
            {
                return keys;
            }

            Span<byte> encryptedKey = stackalloc byte[Base64Url.GetArraySizeRequiredToDecode(rawEncryptedKey.Length)];
            var operationResult = Base64Url.Base64UrlDecode(rawEncryptedKey, encryptedKey, out int bytesConsumed, out int bytesWritten);
            Debug.Assert(operationResult == OperationStatus.Done);

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

        private static uint ComputeHash(ReadOnlySpan<byte> data)
        {
            uint num = 0;
            if (data != null)
            {
                num = 2166136261U;
                for (int index = 0; index < data.Length; ++index)
                {
                    num = (uint)((data[index] ^ (int)num) * 16777619);
                }
            }

            return num;
        }
    }
}