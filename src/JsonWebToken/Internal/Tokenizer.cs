// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Buffers;

namespace JsonWebToken.Internal
{
    internal static class Tokenizer
    {
        private const byte dot = (byte)'.';

        public static int Tokenize(ReadOnlySpan<byte> token, Span<TokenSegment> segments, int maxCount)
        {
            int count = 0;
            int start = 0;
            int end;
            var span = token;
            while ((end = span.IndexOf(dot)) >= 0 && count < maxCount)
            {
                segments[count++] = new TokenSegment(start, end);
                start += end + 1;
                span = token.Slice(start);
            }

            // Residue
            var length = span.Length;
            if (count < maxCount)
            {
                segments[count++] = new TokenSegment(start, length);
            }

            return count;
        }

        public static int Tokenize(ReadOnlySequence<byte> token, Span<TokenSegment> segments, int maxCount)
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
                while ((end = span.IndexOf(dot)) >= 0 && count < maxCount)
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
            if (count < maxCount)
            {
                segments[count++] = new TokenSegment(start, length);
            }

            return count;
        }
    }
}