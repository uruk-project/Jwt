// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if !NETSTANDARD2_0
using System.Text.Encodings.Web;
#endif
using System.Text.Json;

namespace JsonWebToken
{
    internal static class Constants
    {
        internal const int JweSegmentCount = 5;

        internal const int JwsSegmentCount = 3;

        internal const int MaxStackallocBytes = 256;

        internal const int DecompressionBufferLength = 1024;

        internal const byte ByteDot = (byte)'.';

#if !NETSTANDARD2_0
        public static readonly JavaScriptEncoder JsonEncoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping;
#endif

        internal static readonly JsonWriterOptions NoJsonValidation = new JsonWriterOptions
        {
#if !NETSTANDARD2_0
            Encoder = JsonEncoder,
#endif
            SkipValidation = true
        };
    }
}
