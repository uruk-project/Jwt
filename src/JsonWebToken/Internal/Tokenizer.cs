// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Runtime.CompilerServices;

namespace JsonWebToken
{
    internal static class Tokenizer
    {
        public static int Tokenize(ReadOnlySpan<byte> token, ref TokenSegment segments)
        {
            int start;
            var span = token;
            int last = span.LastIndexOf(Constants.ByteDot);
            int end = span.IndexOf(Constants.ByteDot);
            if (end < 0)
            {
                return 0;
            }

            segments = new TokenSegment(0, end);
            start = end + 1;
            span = token.Slice(start);
            end = span.IndexOf(Constants.ByteDot);
            if (end < 0)
            {
                return 0;
            }

            Unsafe.Add(ref segments, 1) = new TokenSegment(start, end);
            start += end + 1;
            if (last == start - 1)
            {
                Unsafe.Add(ref segments, 2) = new TokenSegment(last + 1, token.Length - last - 1);
                return Constants.JwsSegmentCount;
            }

            span = token.Slice(start);
            end = span.IndexOf(Constants.ByteDot);
            if (end < 0)
            {
                return 0;
            }

            Unsafe.Add(ref segments, 2) = new TokenSegment(start, end);
            start += end + 1;
            span = token.Slice(start);

            end = span.IndexOf(Constants.ByteDot);
            if (end < 0)
            {
                return 0;
            }

            Unsafe.Add(ref segments, 3) = new TokenSegment(start, end);
            start += end + 1;
            if (last == start - 1)
            {
                Unsafe.Add(ref segments, 4) = new TokenSegment(last + 1, token.Length - last - 1);
                return Constants.JweSegmentCount;
            }

            return 0;
        }
    }
}