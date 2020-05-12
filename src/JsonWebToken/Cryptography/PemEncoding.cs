﻿//using System;
//using System.Buffers;
//using System.Diagnostics;
//using System.Runtime.CompilerServices;

//namespace JsonWebToken.Cryptography
//{
//    internal static class PemLabels
//    {
//        internal const string Pkcs8PrivateKey = "PRIVATE KEY";
//        internal const string EncryptedPkcs8PrivateKey = "ENCRYPTED PRIVATE KEY";
//        internal const string SpkiPublicKey = "PUBLIC KEY";
//        internal const string RsaPublicKey = "RSA PUBLIC KEY";
//        internal const string RsaPrivateKey = "RSA PRIVATE KEY";
//        internal const string EcPrivateKey = "EC PRIVATE KEY";
//    }

//    /// From https://github.com/dotnet/runtime/blob/master/src/libraries/System.Security.Cryptography.Encoding/src/System/Security/Cryptography/PemEncoding.cs
//    internal class PemReader
//    {
//        public delegate void ImportKeyAction(ReadOnlySpan<byte> source, out int bytesRead);
//        public delegate ImportKeyAction? FindImportActionFunc(ReadOnlySpan<char> label);
//        public delegate void ImportEncryptedKeyAction<TPass>(
//            ReadOnlySpan<TPass> password,
//            ReadOnlySpan<byte> source,
//            out int bytesRead);

//        public static void ImportEncryptedPem<TPass>(
//            ReadOnlySpan<char> input,
//            ReadOnlySpan<TPass> password,
//            ImportEncryptedKeyAction<TPass> importAction)
//        {
//            bool foundEncryptedPem = false;
//            PemFields foundFields = default;
//            ReadOnlySpan<char> foundSlice = default;

//            ReadOnlySpan<char> pem = input;
//            while (PemEncoding.TryFind(pem, out PemFields fields))
//            {
//                ReadOnlySpan<char> label = pem[fields.Label];

//                if (label.SequenceEqual(PemLabels.EncryptedPkcs8PrivateKey))
//                {
//                    if (foundEncryptedPem)
//                    {
//                        ThrowHelper.ThrowArgumentException_AmbiguousPem(nameof(input));
//                    }

//                    foundEncryptedPem = true;
//                    foundFields = fields;
//                    foundSlice = pem;
//                }

//                Index offset = fields.Location.End;
//                pem = pem[offset..];
//            }

//            if (!foundEncryptedPem)
//            {
//                ThrowHelper.ThrowArgumentException_NoPemFound(nameof(input));
//            }

//            ReadOnlySpan<char> base64Contents = foundSlice[foundFields.Base64Data];
//            int base64size = foundFields.DecodedDataLength;
//            byte[] decodeBuffer = ArrayPool<byte>.Shared.Rent(base64size);
//            int bytesWritten = 0;

//            try
//            {
//                if (!Convert.TryFromBase64Chars(base64Contents, decodeBuffer, out bytesWritten))
//                {
//                    // Couldn't decode base64. We shouldn't get here since the
//                    // contents are pre-validated.
//                    Debug.Fail("Base64 decoding failed on already validated contents.");
//                    throw new ArgumentException();
//                }

//                Debug.Assert(bytesWritten == base64size);
//                Span<byte> decodedBase64 = decodeBuffer.AsSpan(0, bytesWritten);

//                // Don't need to check the bytesRead here. We're already operating
//                // on an input which is already a parsed subset of the input.
//                importAction(password, decodedBase64, out _);
//            }
//            finally
//            {
//                ArrayPool<byte>.Shared.Return(decodeBuffer);
//            }
//        }

//        public static void ImportPem(ReadOnlySpan<char> input, FindImportActionFunc callback)
//        {
//            ImportKeyAction? importAction = null;
//            PemFields foundFields = default;
//            ReadOnlySpan<char> foundSlice = default;
//            bool containsEncryptedPem = false;

//            ReadOnlySpan<char> pem = input;
//            while (PemEncoding.TryFind(pem, out PemFields fields))
//            {
//                ReadOnlySpan<char> label = pem[fields.Label];
//                ImportKeyAction? action = callback(label);

//                // Caller knows how to handle this PEM by label.
//                if (action != null)
//                {
//                    // There was a previous PEM that could have been handled,
//                    // which means this is ambiguous and contains multiple
//                    // importable keys. Or, this contained an encrypted PEM.
//                    // For purposes of encrypted PKCS8 with another actionable
//                    // PEM, we will throw a duplicate exception.
//                    if (importAction != null || containsEncryptedPem)
//                    {
//                        ThrowHelper.ThrowArgumentException_AmbiguousPem(nameof(input));
//                    }

//                    importAction = action;
//                    foundFields = fields;
//                    foundSlice = pem;
//                }
//                else if (label.SequenceEqual(PemLabels.EncryptedPkcs8PrivateKey))
//                {
//                    if (importAction != null || containsEncryptedPem)
//                    {
//                        ThrowHelper.ThrowArgumentException_AmbiguousPem(nameof(input));
//                    }

//                    containsEncryptedPem = true;
//                }

//                Index offset = fields.Location.End;
//                pem = pem[offset..];
//            }

//            // The only PEM found that could potentially be used is encrypted PKCS8,
//            // but we won't try to import it with a null or blank password, so
//            // throw.
//            if (containsEncryptedPem)
//            {
//                ThrowHelper.ThrowArgumentException_EncryptedPem(nameof(input));
//            }

//            // We went through the PEM and found nothing that could be handled.
//            if (importAction is null)
//            {
//                ThrowHelper.ThrowArgumentException_NoPemFound(nameof(input));
//            }

//            ReadOnlySpan<char> base64Contents = foundSlice[foundFields.Base64Data];
//            int base64size = foundFields.DecodedDataLength;
//            byte[] decodeBuffer = ArrayPool<byte>.Shared.Rent(base64size);
//            int bytesWritten = 0;

//            try
//            {
//                if (!Convert.TryFromBase64Chars(base64Contents, decodeBuffer, out bytesWritten))
//                {
//                    // Couldn't decode base64. We shouldn't get here since the
//                    // contents are pre-validated.
//                    Debug.Fail("Base64 decoding failed on already validated contents.");
//                    throw new ArgumentException();
//                }

//                Debug.Assert(bytesWritten == base64size);
//                Span<byte> decodedBase64 = decodeBuffer.AsSpan(0, bytesWritten);

//                // Don't need to check the bytesRead here. We're already operating
//                // on an input which is already a parsed subset of the input.
//                importAction(decodedBase64, out _);
//            }
//            finally
//            {
//                ArrayPool<byte>.Shared.Return(decodeBuffer);
//            }
//        }
//    }


//    /// <summary>
//    /// Provides methods for reading and writing the IETF RFC 7468
//    /// subset of PEM (Privacy-Enhanced Mail) textual encodings.
//    /// This class cannot be inherited.
//    /// </summary>
//    internal static class PemEncoding
//    {
//        private const string PreEBPrefix = "-----BEGIN ";
//        private const string PostEBPrefix = "-----END ";
//        private const string Ending = "-----";
//        private const int EncodedLineLength = 64;

//        /// <summary>
//        /// Finds the first PEM-encoded data.
//        /// </summary>
//        /// <param name="pemData">
//        /// The text containing the PEM-encoded data.
//        /// </param>
//        /// <exception cref="ArgumentException">
//        /// <paramref name="pemData"/> does not contain a well-formed PEM-encoded value.
//        /// </exception>
//        /// <returns>
//        /// A value that specifies the location, label, and data location of
//        /// the encoded data.
//        /// </returns>
//        /// <remarks>
//        /// IETF RFC 7468 permits different decoding rules. This method
//        /// always uses lax rules.
//        /// </remarks>
//        public static PemFields Find(ReadOnlySpan<char> pemData)
//        {
//            if (!TryFind(pemData, out PemFields fields))
//            {
//                ThrowHelper.ThrowArgumentException_NoPemFound(nameof(pemData));
//            }

//            return fields;
//        }

//        /// <summary>
//        /// Attempts to find the first PEM-encoded data.
//        /// </summary>
//        /// <param name="pemData">
//        /// The text containing the PEM-encoded data.
//        /// </param>
//        /// <param name="fields">
//        /// When this method returns, contains a value
//        /// that specifies the location, label, and data location of the encoded data;
//        /// or that specifies those locations as empty if no PEM-encoded data is found.
//        /// This parameter is treated as uninitialized.
//        /// </param>
//        /// <returns>
//        /// <c>true</c> if PEM-encoded data was found; otherwise <c>false</c>.
//        /// </returns>
//        /// <remarks>
//        /// IETF RFC 7468 permits different decoding rules. This method
//        /// always uses lax rules.
//        /// </remarks>
//        public static bool TryFind(ReadOnlySpan<char> pemData, out PemFields fields)
//        {
//            // Check for the minimum possible encoded length of a PEM structure
//            // and exit early if there is no way the input could contain a well-formed
//            // PEM.
//            if (pemData.Length < PreEBPrefix.Length + Ending.Length * 2 + PostEBPrefix.Length)
//            {
//                fields = default;
//                return false;
//            }

//            const int PostebStackBufferSize = 256;
//            Span<char> postebStackBuffer = stackalloc char[PostebStackBufferSize];
//            int areaOffset = 0;
//            int preebIndex;
//            while ((preebIndex = pemData.IndexOfByOffset(PreEBPrefix, areaOffset)) >= 0)
//            {
//                int labelStartIndex = preebIndex + PreEBPrefix.Length;

//                // If there are any previous characters, the one prior to the PreEB
//                // must be a white space character.
//                if (preebIndex > 0 && !IsWhiteSpaceCharacter(pemData[preebIndex - 1]))
//                {
//                    areaOffset += labelStartIndex;
//                    continue;
//                }

//                int preebEndIndex = pemData.IndexOfByOffset(Ending, labelStartIndex);

//                // There is no ending sequence, -----, in the remainder of
//                // the document. Therefore, there can never be a complete PreEB
//                // and we can exit.
//                if (preebEndIndex < 0)
//                {
//                    fields = default;
//                    return false;
//                }

//                Range labelRange = labelStartIndex..preebEndIndex;
//                ReadOnlySpan<char> label = pemData[labelRange];

//                // There could be a preeb that is valid after this one if it has an invalid
//                // label, so move from there.
//                if (!IsValidLabel(label))
//                {
//                    goto NextAfterLabel;
//                }

//                int contentStartIndex = preebEndIndex + Ending.Length;
//                int postebLength = PostEBPrefix.Length + label.Length + Ending.Length;

//                Span<char> postebBuffer = postebLength > PostebStackBufferSize
//                    ? new char[postebLength]
//                    : postebStackBuffer;
//                ReadOnlySpan<char> posteb = WritePostEB(label, postebBuffer);
//                int postebStartIndex = pemData.IndexOfByOffset(posteb, contentStartIndex);

//                if (postebStartIndex < 0)
//                {
//                    goto NextAfterLabel;
//                }

//                int pemEndIndex = postebStartIndex + postebLength;

//                // The PostEB must either end at the end of the string, or
//                // have at least one white space character after it.
//                if (pemEndIndex < pemData.Length - 1 &&
//                    !IsWhiteSpaceCharacter(pemData[pemEndIndex]))
//                {
//                    goto NextAfterLabel;
//                }

//                Range contentRange = contentStartIndex..postebStartIndex;

//                if (!TryCountBase64(pemData[contentRange], out int base64start, out int base64end, out int decodedSize))
//                {
//                    goto NextAfterLabel;
//                }

//                Range pemRange = preebIndex..pemEndIndex;
//                Range base64range = (contentStartIndex + base64start)..(contentStartIndex + base64end);
//                fields = new PemFields(labelRange, base64range, pemRange, decodedSize);
//                return true;

//            NextAfterLabel:
//                if (preebEndIndex <= 0)
//                {
//                    // We somehow ended up in a situation where we will advance
//                    // 0 or -1 characters, which means we'll probably end up here again,
//                    // advancing 0 or -1 characters, in a loop. To avoid getting stuck,
//                    // detect this situation and return.
//                    fields = default;
//                    return false;
//                }
//                areaOffset += preebEndIndex;
//            }

//            fields = default;
//            return false;

//            static ReadOnlySpan<char> WritePostEB(ReadOnlySpan<char> label, Span<char> destination)
//            {
//                int size = PostEBPrefix.Length + label.Length + Ending.Length;
//                Debug.Assert(destination.Length >= size);
//                PostEBPrefix.AsSpan().CopyTo(destination);
//                label.CopyTo(destination.Slice(PostEBPrefix.Length));
//                Ending.AsSpan().CopyTo(destination.Slice(PostEBPrefix.Length + label.Length));
//                return destination.Slice(0, size);
//            }
//        }

//        private static int IndexOfByOffset(this ReadOnlySpan<char> str, ReadOnlySpan<char> value, int startPosition)
//        {
//            int index = str.Slice(startPosition).IndexOf(value);
//            return index == -1 ? -1 : index + startPosition;
//        }

//        private static bool IsValidLabel(ReadOnlySpan<char> data)
//        {
//            static bool IsLabelChar(char c) => (uint)(c - 0x21u) <= 0x5du && c != '-';

//            // Empty labels are permitted per RFC 7468.
//            if (data.IsEmpty)
//                return true;

//            // The first character must be a labelchar, so initialize to false
//            bool previousIsLabelChar = false;

//            for (int index = 0; index < data.Length; index++)
//            {
//                char c = data[index];

//                if (IsLabelChar(c))
//                {
//                    previousIsLabelChar = true;
//                    continue;
//                }

//                bool isSpaceOrHyphen = c == ' ' || c == '-';

//                // IETF RFC 7468 states that every character in a label must
//                // be a labelchar, and each labelchar may have zero or one
//                // preceding space or hyphen, except the first labelchar.
//                // If this character is not a space or hyphen, then this characer
//                // is invalid.
//                // If it is a space or hyphen, and the previous character was
//                // also not a labelchar (another hyphen or space), then we have
//                // two consecutive spaces or hyphens which is is invalid.
//                if (!isSpaceOrHyphen || !previousIsLabelChar)
//                {
//                    return false;
//                }

//                previousIsLabelChar = false;
//            }

//            // The last character must also be a labelchar. It cannot be a
//            // hyphen or space since these are only allowed to precede
//            // a labelchar.
//            return previousIsLabelChar;
//        }

//        private static bool TryCountBase64(
//            ReadOnlySpan<char> str,
//            out int base64Start,
//            out int base64End,
//            out int base64DecodedSize)
//        {
//            base64Start = 0;
//            base64End = str.Length;

//            if (str.IsEmpty)
//            {
//                base64DecodedSize = 0;
//                return true;
//            }

//            int significantCharacters = 0;
//            int paddingCharacters = 0;

//            for (int i = 0; i < str.Length; i++)
//            {
//                char ch = str[i];

//                if (IsWhiteSpaceCharacter(ch))
//                {
//                    if (significantCharacters == 0)
//                    {
//                        base64Start++;
//                    }
//                    else
//                    {
//                        base64End--;
//                    }

//                    continue;
//                }

//                base64End = str.Length;

//                if (ch == '=')
//                {
//                    paddingCharacters++;
//                }
//                else if (paddingCharacters == 0 && IsBase64Character(ch))
//                {
//                    significantCharacters++;
//                }
//                else
//                {
//                    base64DecodedSize = 0;
//                    return false;
//                }
//            }

//            int totalChars = paddingCharacters + significantCharacters;

//            if (paddingCharacters > 2 || (totalChars & 0b11) != 0)
//            {
//                base64DecodedSize = 0;
//                return false;
//            }

//            base64DecodedSize = (totalChars >> 2) * 3 - paddingCharacters;
//            return true;
//        }

//        [MethodImpl(MethodImplOptions.AggressiveInlining)]
//        private static bool IsBase64Character(char ch)
//        {
//            uint c = (uint)ch;
//            return c == '+' || c == '/' ||
//                   c - '0' < 10 || c - 'A' < 26 || c - 'a' < 26;
//        }

//        [MethodImpl(MethodImplOptions.AggressiveInlining)]
//        private static bool IsWhiteSpaceCharacter(char ch)
//        {
//            // Match white space characters from Convert.Base64
//            return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r';
//        }

//        /// <summary>
//        /// Determines the length of a PEM-encoded value, in characters,
//        /// given the length of a label and binary data.
//        /// </summary>
//        /// <param name="labelLength">
//        /// The length of the label, in characters.
//        /// </param>
//        /// <param name="dataLength">
//        /// The length of the data, in bytes.
//        /// </param>
//        /// <returns>
//        /// The number of characters in the encoded PEM.
//        /// </returns>
//        /// <exception cref="ArgumentOutOfRangeException">
//        ///   <paramref name="labelLength"/> is a negative value.
//        ///   <para>
//        ///       -or-
//        ///   </para>
//        ///   <paramref name="dataLength"/> is a negative value.
//        ///   <para>
//        ///       -or-
//        ///   </para>
//        ///   <paramref name="labelLength"/> exceeds the maximum possible label length.
//        ///   <para>
//        ///       -or-
//        ///   </para>
//        ///   <paramref name="dataLength"/> exceeds the maximum possible encoded data length.
//        /// </exception>
//        /// <exception cref="ArgumentException">
//        /// The length of the PEM-encoded value is larger than <see cref="int.MaxValue"/>.
//        /// </exception>
//        private static int GetEncodedSize(int labelLength, int dataLength)
//        {
//            // The largest possible label is MaxLabelSize - when included in the posteb
//            // and preeb lines new lines, assuming the base64 content is empty.
//            //     -----BEGIN {char * MaxLabelSize}-----\n
//            //     -----END {char * MaxLabelSize}-----
//            const int MaxLabelSize = 1_073_741_808;

//            // The largest possible binary value to fit in a padded base64 string
//            // is 1,610,612,733 bytes. RFC 7468 states:
//            //   Generators MUST wrap the base64-encoded lines so that each line
//            //   consists of exactly 64 characters except for the final line
//            // We need to account for new line characters, every 64 characters.
//            // This works out to 1,585,834,053 maximum bytes in data when wrapping
//            // is accounted for assuming an empty label.
//            const int MaxDataLength = 1_585_834_053;

//            if (labelLength > MaxLabelSize)
//                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(labelLength));
//            if (dataLength > MaxDataLength)
//                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(dataLength));

//            int preebLength = PreEBPrefix.Length + labelLength + Ending.Length;
//            int postebLength = PostEBPrefix.Length + labelLength + Ending.Length;
//            int totalEncapLength = preebLength + postebLength + 1; //Add one for newline after preeb

//            // dataLength is already known to not overflow here
//            int encodedDataLength = ((dataLength + 2) / 3) << 2;
//            int lineCount = Math.DivRem(encodedDataLength, EncodedLineLength, out int remainder);

//            if (remainder > 0)
//                lineCount++;

//            int encodedDataLengthWithBreaks = encodedDataLength + lineCount;

//            if (int.MaxValue - encodedDataLengthWithBreaks < totalEncapLength)
//                ThrowHelper.ThrowArgumentOutOfRangeException_MustBeAtLeast(ExceptionArgument.size, int.MaxValue - encodedDataLengthWithBreaks);

//            return encodedDataLengthWithBreaks + totalEncapLength;
//        }

//        /// <summary>
//        /// Tries to write the provided data and label as PEM-encoded data into
//        /// a provided buffer.
//        /// </summary>
//        /// <param name="label">
//        /// The label to write.
//        /// </param>
//        /// <param name="data">
//        /// The data to write.
//        /// </param>
//        /// <param name="destination">
//        /// The buffer to receive the PEM-encoded text.
//        /// </param>
//        /// <param name="charsWritten">
//        /// When this method returns, this parameter contains the number of characters
//        /// written to <paramref name="destination"/>. This parameter is treated
//        /// as uninitialized.
//        /// </param>
//        /// <returns>
//        /// <c>true</c> if <paramref name="destination"/> is large enough to contain
//        /// the PEM-encoded text, otherwise <c>false</c>.
//        /// </returns>
//        /// <remarks>
//        /// This method always wraps the base-64 encoded text to 64 characters, per the
//        /// recommended wrapping of IETF RFC 7468. Unix-style line endings are used for line breaks.
//        /// </remarks>
//        /// <exception cref="ArgumentOutOfRangeException">
//        ///   <paramref name="label"/> exceeds the maximum possible label length.
//        ///   <para>
//        ///       -or-
//        ///   </para>
//        ///   <paramref name="data"/> exceeds the maximum possible encoded data length.
//        /// </exception>
//        /// <exception cref="ArgumentException">
//        /// The resulting PEM-encoded text is larger than <see cref="int.MaxValue"/>.
//        ///   <para>
//        ///       - or -
//        ///   </para>
//        /// <paramref name="label"/> contains invalid characters.
//        /// </exception>
//        public static bool TryWrite(ReadOnlySpan<char> label, ReadOnlySpan<byte> data, Span<char> destination, out int charsWritten)
//        {
//            static int Write(ReadOnlySpan<char> str, Span<char> dest, int offset)
//            {
//                str.CopyTo(dest.Slice(offset));
//                return str.Length;
//            }

//            static int WriteBase64(ReadOnlySpan<byte> bytes, Span<char> dest, int offset)
//            {
//                bool success = Convert.TryToBase64Chars(bytes, dest.Slice(offset), out int base64Written);

//                if (!success)
//                {
//                    Debug.Fail("Convert.TryToBase64Chars failed with a pre-sized buffer");
//                    throw new ArgumentException();
//                }

//                return base64Written;
//            }

//            if (!IsValidLabel(label))
//                ThrowHelper.ThrowArgumentException_InvalidLabel(nameof(label));

//            const string NewLine = "\n";
//            const int BytesPerLine = 48;
//            int encodedSize = GetEncodedSize(label.Length, data.Length);

//            if (destination.Length < encodedSize)
//            {
//                charsWritten = 0;
//                return false;
//            }

//            charsWritten = 0;
//            charsWritten += Write(PreEBPrefix, destination, charsWritten);
//            charsWritten += Write(label, destination, charsWritten);
//            charsWritten += Write(Ending, destination, charsWritten);
//            charsWritten += Write(NewLine, destination, charsWritten);

//            ReadOnlySpan<byte> remainingData = data;
//            while (remainingData.Length >= BytesPerLine)
//            {
//                charsWritten += WriteBase64(remainingData.Slice(0, BytesPerLine), destination, charsWritten);
//                charsWritten += Write(NewLine, destination, charsWritten);
//                remainingData = remainingData.Slice(BytesPerLine);
//            }

//            Debug.Assert(remainingData.Length < BytesPerLine);

//            if (remainingData.Length > 0)
//            {
//                charsWritten += WriteBase64(remainingData, destination, charsWritten);
//                charsWritten += Write(NewLine, destination, charsWritten);
//                remainingData = default;
//            }

//            charsWritten += Write(PostEBPrefix, destination, charsWritten);
//            charsWritten += Write(label, destination, charsWritten);
//            charsWritten += Write(Ending, destination, charsWritten);

//            return true;
//        }

//        /// <summary>
//        /// Creates an encoded PEM with the given label and data.
//        /// </summary>
//        /// <param name="label">
//        /// The label to encode.
//        /// </param>
//        /// <param name="data">
//        /// The data to encode.
//        /// </param>
//        /// <returns>
//        /// A character array of the encoded PEM.
//        /// </returns>
//        /// <remarks>
//        /// This method always wraps the base-64 encoded text to 64 characters, per the
//        /// recommended wrapping of RFC-7468. Unix-style line endings are used for line breaks.
//        /// </remarks>
//        /// <exception cref="ArgumentOutOfRangeException">
//        ///   <paramref name="label"/> exceeds the maximum possible label length.
//        ///   <para>
//        ///       -or-
//        ///   </para>
//        ///   <paramref name="data"/> exceeds the maximum possible encoded data length.
//        /// </exception>
//        /// <exception cref="ArgumentException">
//        /// The resulting PEM-encoded text is larger than <see cref="int.MaxValue"/>.
//        ///   <para>
//        ///       - or -
//        ///   </para>
//        /// <paramref name="label"/> contains invalid characters.
//        /// </exception>
//        public static char[] Write(ReadOnlySpan<char> label, ReadOnlySpan<byte> data)
//        {
//            if (!IsValidLabel(label))
//                ThrowHelper.ThrowArgumentException_InvalidLabel(nameof(label));

//            int encodedSize = GetEncodedSize(label.Length, data.Length);
//            char[] buffer = new char[encodedSize];

//            if (!TryWrite(label, data, buffer, out int charsWritten))
//            {
//                Debug.Fail("TryWrite failed with a pre-sized buffer");
//                throw new ArgumentException();
//            }

//            Debug.Assert(charsWritten == encodedSize);
//            return buffer;
//        }
//    }

//    /// <summary>
//    /// Contains information about the location of PEM data.
//    /// </summary>
//    internal readonly struct PemFields
//    {
//        internal PemFields(Range label, Range base64data, Range location, int decodedDataLength)
//        {
//            Location = location;
//            DecodedDataLength = decodedDataLength;
//            Base64Data = base64data;
//            Label = label;
//        }

//        /// <summary>
//        /// Gets the location of the PEM-encoded text, including the surrounding encapsulation boundaries.
//        /// </summary>
//        public Range Location { get; }

//        /// <summary>
//        /// Gets the location of the label.
//        /// </summary>
//        public Range Label { get; }

//        /// <summary>
//        /// Gets the location of the base-64 data inside of the PEM.
//        /// </summary>
//        public Range Base64Data { get; }

//        /// <summary>
//        /// Gets the size of the decoded base-64 data, in bytes.
//        /// </summary>
//        public int DecodedDataLength { get; }
//    }

//    internal static class PemKeyImportHelpers
//    {
//        public delegate void ImportKeyAction(ReadOnlySpan<byte> source, out int bytesRead);
//        public delegate ImportKeyAction? FindImportActionFunc(ReadOnlySpan<char> label);
//        public delegate void ImportEncryptedKeyAction<TPass>(
//            ReadOnlySpan<TPass> password,
//            ReadOnlySpan<byte> source,
//            out int bytesRead);

//        public static void ImportEncryptedPem<TPass>(
//            ReadOnlySpan<char> input,
//            ReadOnlySpan<TPass> password,
//            ImportEncryptedKeyAction<TPass> importAction)
//        {
//            bool foundEncryptedPem = false;
//            PemFields foundFields = default;
//            ReadOnlySpan<char> foundSlice = default;

//            ReadOnlySpan<char> pem = input;
//            while (PemEncoding.TryFind(pem, out PemFields fields))
//            {
//                ReadOnlySpan<char> label = pem[fields.Label];

//                if (label.SequenceEqual(PemLabels.EncryptedPkcs8PrivateKey))
//                {
//                    if (foundEncryptedPem)
//                    {
//                        ThrowHelper.ThrowArgumentException_AmbiguousPem(nameof(input));
//                    }

//                    foundEncryptedPem = true;
//                    foundFields = fields;
//                    foundSlice = pem;
//                }

//                Index offset = fields.Location.End;
//                pem = pem[offset..];
//            }

//            if (!foundEncryptedPem)
//            {
//                ThrowHelper.ThrowArgumentException_NoPemFound(nameof(input));
//            }

//            ReadOnlySpan<char> base64Contents = foundSlice[foundFields.Base64Data];
//            int base64size = foundFields.DecodedDataLength;
//            byte[] decodeBuffer = ArrayPool<byte>.Shared.Rent(base64size);
//            int bytesWritten = 0;

//            try
//            {
//                if (!Convert.TryFromBase64Chars(base64Contents, decodeBuffer, out bytesWritten))
//                {
//                    // Couldn't decode base64. We shouldn't get here since the
//                    // contents are pre-validated.
//                    Debug.Fail("Base64 decoding failed on already validated contents.");
//                    throw new ArgumentException();
//                }

//                Debug.Assert(bytesWritten == base64size);
//                Span<byte> decodedBase64 = decodeBuffer.AsSpan(0, bytesWritten);

//                // Don't need to check the bytesRead here. We're already operating
//                // on an input which is already a parsed subset of the input.
//                importAction(password, decodedBase64, out _);
//            }
//            finally
//            {
//                ArrayPool<byte>.Shared.Return(decodeBuffer);
//            }
//        }

//        public static void ImportPem(ReadOnlySpan<char> input, FindImportActionFunc callback)
//        {
//            ImportKeyAction? importAction = null;
//            PemFields foundFields = default;
//            ReadOnlySpan<char> foundSlice = default;
//            bool containsEncryptedPem = false;

//            ReadOnlySpan<char> pem = input;
//            while (PemEncoding.TryFind(pem, out PemFields fields))
//            {
//                ReadOnlySpan<char> label = pem[fields.Label];
//                ImportKeyAction? action = callback(label);

//                // Caller knows how to handle this PEM by label.
//                if (action != null)
//                {
//                    // There was a previous PEM that could have been handled,
//                    // which means this is ambiguous and contains multiple
//                    // importable keys. Or, this contained an encrypted PEM.
//                    // For purposes of encrypted PKCS8 with another actionable
//                    // PEM, we will throw a duplicate exception.
//                    if (importAction != null || containsEncryptedPem)
//                    {
//                        ThrowHelper.ThrowArgumentException_AmbiguousPem(nameof(input));
//                    }

//                    importAction = action;
//                    foundFields = fields;
//                    foundSlice = pem;
//                }
//                else if (label.SequenceEqual(PemLabels.EncryptedPkcs8PrivateKey))
//                {
//                    if (importAction != null || containsEncryptedPem)
//                    {
//                        ThrowHelper.ThrowArgumentException_AmbiguousPem(nameof(input));
//                    }

//                    containsEncryptedPem = true;
//                }

//                Index offset = fields.Location.End;
//                pem = pem[offset..];
//            }

//            // The only PEM found that could potentially be used is encrypted PKCS8,
//            // but we won't try to import it with a null or blank password, so
//            // throw.
//            if (containsEncryptedPem)
//            {
//                ThrowHelper.ThrowArgumentException_EncryptedPem(nameof(input));
//            }

//            // We went through the PEM and found nothing that could be handled.
//            if (importAction is null)
//            {
//                ThrowHelper.ThrowArgumentException_NoPemFound(nameof(input));
//            }

//            ReadOnlySpan<char> base64Contents = foundSlice[foundFields.Base64Data];
//            int base64size = foundFields.DecodedDataLength;
//            byte[] decodeBuffer = ArrayPool<byte>.Shared.Rent(base64size);
//            int bytesWritten = 0;

//            try
//            {
//                if (!Convert.TryFromBase64Chars(base64Contents, decodeBuffer, out bytesWritten))
//                {
//                    // Couldn't decode base64. We shouldn't get here since the
//                    // contents are pre-validated.
//                    Debug.Fail("Base64 decoding failed on already validated contents.");
//                    throw new ArgumentException();
//                }

//                Debug.Assert(bytesWritten == base64size);
//                Span<byte> decodedBase64 = decodeBuffer.AsSpan(0, bytesWritten);

//                // Don't need to check the bytesRead here. We're already operating
//                // on an input which is already a parsed subset of the input.
//                importAction(decodedBase64, out _);
//            }
//            finally
//            {
//                ArrayPool<byte>.Shared.Return(decodeBuffer);
//            }
//        }
//    }
//}
