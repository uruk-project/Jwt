// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Text.Encodings.Web;
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

        public static readonly JavaScriptEncoder JsonEncoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping;

        internal static readonly JsonWriterOptions NoJsonValidation = new JsonWriterOptions
        {
            Encoder = JsonEncoder,
            SkipValidation = true
        };

        internal static readonly JsonSerializerOptions DefaultSerializerOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = new JsonSnakeCaseNamingPolicy()
        };

        internal const string Jwt = "JWT";
    }
}
