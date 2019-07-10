// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System.Text.Json;

namespace JsonWebToken
{
    internal static class Constants
    {
        internal const int JweSegmentCount = 5;

        internal const int JwsSegmentCount = 3;

        internal const int MaxStackallocBytes = 256;

        internal static readonly int DecompressionBufferLength = 1024;

        internal const byte ByteDot = (byte)'.';

        internal static readonly JsonWriterOptions NoJsonValidation = new JsonWriterOptions { SkipValidation = true };
    }
}
