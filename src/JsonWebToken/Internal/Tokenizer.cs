// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Buffers;

namespace JsonWebToken.Internal
{
    internal static class Tokenizer
    {
        private const byte ByteDot = (byte)'.';

        public unsafe static int Tokenize(ReadOnlySpan<byte> token, TokenSegment* pSegments)
        {
            int start;
            var span = token;
            int last = span.LastIndexOf(ByteDot);
            int end = span.IndexOf(ByteDot);
            if (end < 0)
            {
                return 0;
            }

            *pSegments = new TokenSegment(0, end);
            start = end + 1;
            span = token.Slice(start);
            end = span.IndexOf(ByteDot);
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
            end = span.IndexOf(ByteDot);
            if (end < 0)
            {
                return 0;
            }

            *(pSegments + 2) = new TokenSegment(start, end);
            start += end + 1;
            span = token.Slice(start);

            end = span.IndexOf(ByteDot);
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

        public static int Tokenize(in ReadOnlySequence<byte> token, Span<TokenSegment> segments)
        {
            int count = 0;
            int start = 0;
            int end;
            int sequenceOffset = 0;
            var sequence = token;
            SequencePosition nextPosition = token.Start;
            while (sequence.TryGet(ref nextPosition, out ReadOnlyMemory<byte> memory, advance: true))
            {
                var span = memory.Span;
                while ((end = span.IndexOf(ByteDot)) >= 0 && count < Constants.JweSegmentCount)
                {
                    end += sequenceOffset;
                    segments[count++] = new TokenSegment(start, end);
                    start += end + 1;
                    span = memory.Span.Slice(start);
                }

                sequenceOffset += span.Length;
            }

            // Residue 
            var length = (int)sequence.Length;
            if (count < Constants.JweSegmentCount)
            {
                segments[count++] = new TokenSegment(start, length);
            }

            return count;
        }
    }
}