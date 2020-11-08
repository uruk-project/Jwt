// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if SUPPORT_JAVASCRIPT_ENCODER
using System.Text.Encodings.Web;
#endif
using System.Text.Json;
using System;
using System.Globalization;
using System.Text;

namespace JsonWebToken
{
    internal static class Constants
    {
        internal const int JweSegmentCount = 5;

        internal const int JwsSegmentCount = 3;

        internal const int MaxStackallocBytes = 256;

        internal const int DecompressionBufferLength = 1024;

        internal const byte ByteDot = (byte)'.';

#if SUPPORT_JAVASCRIPT_ENCODER
        public static readonly JavaScriptEncoder JsonEncoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping;
#endif

        internal static readonly JsonWriterOptions NoJsonValidation = new JsonWriterOptions
        {
#if SUPPORT_JAVASCRIPT_ENCODER
            Encoder = JsonEncoder,
#endif
            SkipValidation = true
        };

        internal static readonly JsonSerializerOptions DefaultSerializerOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = new JsonSnakeCaseNamingPolicy()
        };
    }

    internal sealed class JsonSnakeCaseNamingPolicy : JsonNamingPolicy
    {
        public override string ConvertName(string name)
        {
            if (string.IsNullOrEmpty(name))
                return name;

            // Allocates a string builder with the guessed result length,
            // where 5 is the average word length in English, and
            // max(2, length / 5) is the number of underscores.
            StringBuilder builder = new StringBuilder(name.Length + Math.Max(2, name.Length / 5));
            UnicodeCategory? previousCategory = null;

            for (int currentIndex = 0; currentIndex < name.Length; currentIndex++)
            {
                char currentChar = name[currentIndex];
                if (currentChar == '_')
                {
                    builder.Append('_');
                    previousCategory = null;
                    continue;
                }

                UnicodeCategory currentCategory = char.GetUnicodeCategory(currentChar);

                switch (currentCategory)
                {
                    case UnicodeCategory.UppercaseLetter:
                    case UnicodeCategory.TitlecaseLetter:
                        if (previousCategory == UnicodeCategory.SpaceSeparator ||
                            previousCategory == UnicodeCategory.LowercaseLetter ||
                            previousCategory != UnicodeCategory.DecimalDigitNumber &&
                            currentIndex > 0 &&
                            currentIndex + 1 < name.Length &&
                            char.IsLower(name[currentIndex + 1]))
                        {
                            builder.Append('_');
                        }

                        currentChar = char.ToLower(currentChar);
                        break;

                    case UnicodeCategory.LowercaseLetter:
                    case UnicodeCategory.DecimalDigitNumber:
                        if (previousCategory == UnicodeCategory.SpaceSeparator)
                        {
                            builder.Append('_');
                        }
                        break;

                    case UnicodeCategory.Surrogate:
                        break;

                    default:
                        if (previousCategory != null)
                        {
                            previousCategory = UnicodeCategory.SpaceSeparator;
                        }
                        continue;
                }

                builder.Append(currentChar);
                previousCategory = currentCategory;
            }

            return builder.ToString();
        }
    }
}
