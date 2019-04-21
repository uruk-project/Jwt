// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Buffers;

namespace JsonWebToken.Internal
{
    internal static class Tokenizer
    {
        public unsafe static int Tokenize(ReadOnlySpan<byte> token, TokenSegment* pSegments)
        {
            int start;
            var span = token;
            int last = span.LastIndexOf(Constants.ByteDot);
            int end = span.IndexOf(Constants.ByteDot);
            if (end < 0)
            {
                return 0;
            }

            *pSegments = new TokenSegment(0, end);
            start = end + 1;
            span = token.Slice(start);
            end = span.IndexOf(Constants.ByteDot);
            if (end < 0)
            {
                return 0;
            }

            *(pSegments + 1) = new TokenSegment(start, end);
            start += end + 1;
            if (last == start - 1)
            {
                *(pSegments + 2) = new TokenSegment(last + 1, token.Length - last - 1);
                return Constants.JwsSegmentCount;
            }

            span = token.Slice(start);
            end = span.IndexOf(Constants.ByteDot);
            if (end < 0)
            {
                return 0;
            }

            *(pSegments + 2) = new TokenSegment(start, end);
            start += end + 1;
            span = token.Slice(start);

            end = span.IndexOf(Constants.ByteDot);
            if (end < 0)
            {
                return 0;
            }

            *(pSegments + 3) = new TokenSegment(start, end);
            start += end + 1;
            if (last == start - 1)
            {
                *(pSegments + 4) = new TokenSegment(last + 1, token.Length - last - 1);
                return Constants.JweSegmentCount;
            }

            return 0;
        }

        public unsafe static int Tokenize(in ReadOnlySequence<byte> token, TokenSegment* pSegments)
        {
            int start;
            var span = token;
            //int last = (int)span.LastIndexOf(ByteDot);
            int end = (int)span.IndexOf(Constants.ByteDot);
            if (end < 0)
            {
                return 0;
            }

            *pSegments = new TokenSegment(0, end);
            start = end + 1;
            span = token.Slice(start);
            end = (int)span.IndexOf(Constants.ByteDot);
            if (end < 0)
            {
                return 0;
            }


            *(pSegments + 1) = new TokenSegment(start, end);
            start += end + 1;
            span = token.Slice(start);
            end = (int)span.IndexOf(Constants.ByteDot);
            if (end < 0)
            {
                *(pSegments + 2) = new TokenSegment(start, (int)span.Length);
                return Constants.JwsSegmentCount;
            }

            *(pSegments + 2) = new TokenSegment(start, end);
            start += end + 1;
            span = token.Slice(start);

            end = (int)span.IndexOf(Constants.ByteDot);
            if (end < 0)
            {
                return 0;
            }

            *(pSegments + 3) = new TokenSegment(start, end);
            start += end + 1;
            span = token.Slice(start);

            end = (int)span.IndexOf(Constants.ByteDot);
            if (end < 0)
            {
                *(pSegments + 4) = new TokenSegment(start, (int)span.Length);
                return Constants.JweSegmentCount;
            }

            return 0;
        }
    }
}