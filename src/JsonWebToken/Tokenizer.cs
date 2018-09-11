using System;

namespace JsonWebToken
{
    internal static class Tokenizer
    {
        private const byte dot = 0x2E;
             
        public static unsafe int Tokenize(ReadOnlySpan<byte> token, TokenSegment* segments, int maxCount)
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
    }
}