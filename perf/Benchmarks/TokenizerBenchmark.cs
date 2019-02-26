using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;

namespace JsonWebToken.Performance
{
    public class TokenizerJwsBenchmark : TokenizerBenchmark
    {
        protected override ReadOnlySpan<byte> Token => new byte[] { (byte)'.', (byte)'.' };
    }
    public class TokenizerJweBenchmark : TokenizerBenchmark
    {
        protected override ReadOnlySpan<byte> Token => new byte[] { (byte)'.', (byte)'.', (byte)'.', (byte)'.' };
    }

    [MemoryDiagnoser]
    [MarkdownExporter]
    public abstract class TokenizerBenchmark
    {
        protected abstract ReadOnlySpan<byte> Token { get; }

        private const byte ByteDot = (byte)'.';

        [Benchmark(Baseline = true)]
        public int Tokenize()
        {
            Span<TokenSegment> segments = stackalloc TokenSegment[5];
            return Tokenize(Token, segments);
        }

        [Benchmark]
        public int Tokenize_AvoidLastSlice()
        {
            Span<TokenSegment> segments = stackalloc TokenSegment[5];
            return Tokenize_AvoidLastSlice(Token, segments);
        }

        //[Benchmark]
        //public int Tokenize_AvoidLastSliceV2()
        //{
        //    Span<TokenSegment> segments = stackalloc TokenSegment[5];
        //    return Tokenize_AvoidLastSliceV2(Token, segments);
        //}

        [Benchmark]
        public int Tokenize_AvoidLastSliceV3()
        {
            Span<TokenSegment> segments = stackalloc TokenSegment[5];
            return Tokenize_AvoidLastSliceV3(Token, segments);
        }

        //[Benchmark]
        //public int Tokenize_AvoidLastSlice_ByRef()
        //{
        //    Span<TokenSegment> segments = stackalloc TokenSegment[5];
        //    return Tokenize_AvoidLastSlice_ByRef(Token, ref MemoryMarshal.GetReference(segments));
        //}

        [Benchmark]
        public unsafe int Tokenize_AvoidLastSlice_Unsafe()
        {
            var segments = stackalloc TokenSegment[5];
            return Tokenize_AvoidLastSlice_Unsafe(Token, segments);
        }

        //[Benchmark]
        //public int TokenizeWhileTrue()
        //{
        //    Span<TokenSegment> segments = stackalloc TokenSegment[5];
        //    return Tokenize_WhileTrue(Token, segments);
        //}

        //[Benchmark]
        //public unsafe int Tokenize_Unsafe()
        //{
        //    TokenSegment* segments = stackalloc TokenSegment[5];
        //    return Tokenize_Unsafe(Token, segments);
        //}

        //[Benchmark]
        //public unsafe int Tokenize_ByRef()
        //{
        //    Span<TokenSegment> segments = stackalloc TokenSegment[5];
        //    return Tokenize_ByRef(Token, ref MemoryMarshal.GetReference(segments));
        //}

        [Benchmark]
        public int Tokenize_Unroll()
        {
            Span<TokenSegment> segments = stackalloc TokenSegment[5];
            return Tokenize_Unroll(Token, segments);
        }


        [Benchmark]
        public int Tokenize_Unroll_Goto()
        {
            Span<TokenSegment> segments = stackalloc TokenSegment[5];
            return Tokenize_Unroll_Goto(Token, segments);
        }

        [Benchmark]
        public unsafe int Tokenize_Unroll_Unsafe()
        {
            var segments = stackalloc TokenSegment[5];
            return Tokenize_Unroll_Unsafe(Token, segments);
        }

        [Benchmark]
        public unsafe int Tokenize_Unroll_Unsafe_Goto()
        {
            var segments = stackalloc TokenSegment[5];
            return Tokenize_Unroll_Unsafe_Goto(Token, segments);
        }

        ////[Benchmark]
        //public unsafe int TokenizeUnrollUnsafe()
        //{
        //    TokenSegment* segments = stackalloc TokenSegment[5];
        //    return TokenizeUnrollUnsafe(Token, segments);
        //}

        [Benchmark]
        public int Tokenize_Unroll_ByRef()
        {
            Span<TokenSegment> segments = stackalloc TokenSegment[5];
            return Tokenize_Unroll_ByRef(Token, ref MemoryMarshal.GetReference(segments));
        }

        [Benchmark]
        public int Tokenize_Unroll_ByRef_V2()
        {
            Span<TokenSegment> segments = stackalloc TokenSegment[5];
            return Tokenize_Unroll_ByRef_V2(Token, ref MemoryMarshal.GetReference(segments));
        }

        public static int Tokenize(ReadOnlySpan<byte> token, Span<TokenSegment> segments)
        {
            int count = 0;
            int start = 0;
            int end;
            var span = token;
            while ((end = span.IndexOf(ByteDot)) >= 0 && count < 5)
            {
                segments[count++] = new TokenSegment(start, end);
                start += end + 1;
                span = token.Slice(start);
            }

            // Residue
            if (count < 5)
            {
                segments[count++] = new TokenSegment(start, span.Length);
            }

            return count;
        }

        //public static int Tokenize_AvoidLastSliceV2(ReadOnlySpan<byte> token, Span<TokenSegment> segments)
        //{
        //    int count = 0;
        //    int start = 0;
        //    int end;
        //    int last = token.LastIndexOf(ByteDot);
        //    var span = token;
        //    while ((end = span.IndexOf(ByteDot)) >= 0 && count < 5)
        //    {
        //        segments[count++] = new TokenSegment(start, end);
        //        start += end + 1;
        //        span = token.Slice(start);
        //        if (last == start - 1)
        //        {
        //            break;
        //        }
        //    }

        //    // Residue
        //    if (count < 5)
        //    {
        //        segments[count++] = new TokenSegment(start, span.Length);
        //    }

        //    return 0;
        //}


        public static int Tokenize_AvoidLastSlice(ReadOnlySpan<byte> token, Span<TokenSegment> segments)
        {
            int count = 0;
            int start = 0;
            int end;
            int last = token.LastIndexOf(ByteDot);
            var span = token;
            while ((end = span.IndexOf(ByteDot)) >= 0 && count < 5)
            {
                segments[count++] = new TokenSegment(start, end);
                start += end + 1;
                if (last == start - 1)
                {
                    segments[count++] = new TokenSegment(last + 1, token.Length - last - 1);
                    return count;
                }

                span = token.Slice(start);
            }

            return 0;
        }

        public static int Tokenize_AvoidLastSliceV3(ReadOnlySpan<byte> token, Span<TokenSegment> segments)
        {
            int count = 0;
            int start = 0;
            int end;
            int last = token.LastIndexOf(ByteDot);
            var span = token;
            while ((end = span.IndexOf(ByteDot)) >= 0 && count < 5)
            {
                segments[count++] = new TokenSegment(start, end);
                start += end + 1;
                if (last == start - 1)
                {
                    segments[count++] = new TokenSegment(last + 1, token.Length - last - 1);
                    goto Found;
                }

                span = token.Slice(start);
            }

            return 0;
        Found:
            return count;
        }

        public static int Tokenize_AvoidLastSlice_ByRef(ReadOnlySpan<byte> token, ref TokenSegment segments)
        {
            int count = 0;
            int start = 0;
            int end;
            int last = token.LastIndexOf(ByteDot);
            var span = token;
            while ((end = span.IndexOf(ByteDot)) >= 0 && count < 5)
            {
                Unsafe.Add(ref segments, count++) = new TokenSegment(start, end);
                start += end + 1;
                if (last == start - 1)
                {
                    Unsafe.Add(ref segments, count++) = new TokenSegment(last + 1, token.Length - last - 1);
                    return count;
                }

                span = token.Slice(start);
            }

            return 0;
        }

        public static unsafe int Tokenize_AvoidLastSlice_Unsafe(ReadOnlySpan<byte> token, TokenSegment* pSegments)
        {
            int count = 0;
            int start = 0;
            int end;
            int last = token.LastIndexOf(ByteDot);
            var span = token;
            while ((end = span.IndexOf(ByteDot)) >= 0 && count < 5)
            {
                *(pSegments + count++) = new TokenSegment(start, end);
                start += end + 1;
                if (last == start - 1)
                {
                    *(pSegments + count++) = new TokenSegment(last + 1, token.Length - last - 1);
                    break;
                }

                span = token.Slice(start);
            }

            return count;
        }

        public unsafe static int Tokenize_Unsafe(ReadOnlySpan<byte> token, TokenSegment* pSegments)
        {
            int count = 0;
            int start = 0;
            int end;
            var span = token;
            while ((end = span.IndexOf(ByteDot)) >= 0 && count < 5)
            {
                *(pSegments + count++) = new TokenSegment(start, end);
                start += end + 1;
                span = token.Slice(start);
            }

            // Residue
            if (count < 5)
            {
                *(pSegments + count++) = new TokenSegment(start, span.Length);
            }

            return count;
        }

        public unsafe static int Tokenize_ByRef(ReadOnlySpan<byte> token, ref TokenSegment segments)
        {
            int count = 0;
            int start = 0;
            int end;
            var span = token;
            while ((end = span.IndexOf(ByteDot)) >= 0 && count < 5)
            {
                Unsafe.Add(ref segments, count++) = new TokenSegment(start, end);
                start += end + 1;
                span = token.Slice(start);
            }

            // Residue
            if (count < 5)
            {
                Unsafe.Add(ref segments, count++) = new TokenSegment(start, span.Length);
            }

            return count;
        }

        public static int Tokenize_Unroll(ReadOnlySpan<byte> token, Span<TokenSegment> segments)
        {
            int start;
            var span = token;
            int last = span.LastIndexOf(ByteDot);
            int end = span.IndexOf(ByteDot);
            if (end < 0)
            {
                return 0;
            }

            segments[0] = new TokenSegment(0, end);
            start = end + 1;
            span = token.Slice(start);
            end = span.IndexOf(ByteDot);
            if (end < 0)
            {
                return 0;
            }

            segments[1] = new TokenSegment(start, end);
            start += end + 1;
            if (last == start - 1)
            {
                segments[2] = new TokenSegment(last + 1, token.Length - last - 1);
                return 3;
            }

            span = token.Slice(start);
            end = span.IndexOf(ByteDot);
            if (end < 0)
            {
                return 0;
            }

            segments[2] = new TokenSegment(start, end);
            start += end + 1;
            span = token.Slice(start);

            end = span.IndexOf(ByteDot);
            if (end < 0)
            {
                return 0;
            }

            segments[3] = new TokenSegment(start, end);
            start += end + 1;
            if (last == start - 1)
            {
                segments[4] = new TokenSegment(last + 1, token.Length - last - 1);
                return 5;
            }

            return 0;
        }

        public static int Tokenize_Unroll_Goto(ReadOnlySpan<byte> token, Span<TokenSegment> segments)
        {
            int start;
            var span = token;
            int last = span.LastIndexOf(ByteDot);
            int end = span.IndexOf(ByteDot);
            if (end < 0)
            {
                goto Malformed;
            }

            segments[0] = new TokenSegment(0, end);
            start = end + 1;
            span = token.Slice(start);
            end = span.IndexOf(ByteDot);
            if (end < 0)
            {
                goto Malformed;
            }

            segments[1] = new TokenSegment(start, end);
            start += end + 1;
            if (last == start - 1)
            {
                segments[2] = new TokenSegment(last + 1, token.Length - last - 1);
                goto Jws;
            }

            span = token.Slice(start);
            end = span.IndexOf(ByteDot);
            if (end < 0)
            {
                goto Malformed;
            }

            segments[2] = new TokenSegment(start, end);
            start += end + 1;
            span = token.Slice(start);

            end = span.IndexOf(ByteDot);
            if (end < 0)
            {
                goto Malformed;
            }

            segments[3] = new TokenSegment(start, end);
            start += end + 1;
            if (last == start - 1)
            {
                segments[4] = new TokenSegment(last + 1, token.Length - last - 1);
                goto Jwe;
            }

        Malformed:
            return 0;
        Jws:
            return 3;
        Jwe:
            return 5;
        }

        public unsafe static int Tokenize_Unroll_Unsafe(ReadOnlySpan<byte> token, TokenSegment* pSegments)
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
                return 3;
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
                return 5;
            }

            return 0;
        }

        public unsafe static int Tokenize_Unroll_ByRef(ReadOnlySpan<byte> token, ref TokenSegment segments)
        {
            int start;
            var span = token;
            int last = span.LastIndexOf(ByteDot);
            int end = span.IndexOf(ByteDot);
            if (end < 0)
            {
                return 0;
            }

            segments = new TokenSegment(0, end);
            start = end + 1;
            span = token.Slice(start);
            end = span.IndexOf(ByteDot);
            if (end < 0)
            {
                return 0;
            }

            Unsafe.Add(ref segments, 1) = new TokenSegment(start, end);
            start += end + 1;
            if (last == start - 1)
            {
                Unsafe.Add(ref segments, 2) = new TokenSegment(last + 1, token.Length - last - 1);
                return 3;
            }

            span = token.Slice(start);
            end = span.IndexOf(ByteDot);
            if (end < 0)
            {
                return 0;
            }

            Unsafe.Add(ref segments, 2) = new TokenSegment(start, end);
            start += end + 1;
            span = token.Slice(start);

            end = span.IndexOf(ByteDot);
            if (end < 0)
            {
                return 0;
            }

            Unsafe.Add(ref segments, 3) = new TokenSegment(start, end);
            start += end + 1;
            if (last == start - 1)
            {
                Unsafe.Add(ref segments, 4) = new TokenSegment(last + 1, token.Length - last - 1);
                return 5;
            }

            return 0;
        }

        public unsafe static int Tokenize_Unroll_ByRef_V2(ReadOnlySpan<byte> token, ref TokenSegment segments)
        {
            int start;
            var span = token;
            int end = span.IndexOf(ByteDot);
            if (end < 0)
            {
                return 0;
            }

            segments = new TokenSegment(0, end);
            start = end + 1;
            span = token.Slice(start);
            end = span.IndexOf(ByteDot);
            if (end < 0)
            {
                return 0;
            }

            Unsafe.Add(ref segments, 1) = new TokenSegment(start, end);
            start += end + 1;
            span = token.Slice(start);
            end = span.IndexOf(ByteDot);
            if (end < 0)
            {
                Unsafe.Add(ref segments, 2) = new TokenSegment(start, span.Length);
                return 3;
            }

            Unsafe.Add(ref segments, 2) = new TokenSegment(start, end);
            start += end + 1;
            span = token.Slice(start);

            end = span.IndexOf(ByteDot);
            if (end < 0)
            {
                return 0;
            }

            Unsafe.Add(ref segments, 3) = new TokenSegment(start, end);
            start += end + 1;
            span = token.Slice(start);

            end = span.IndexOf(ByteDot);
            if (end < 0)
            {
                Unsafe.Add(ref segments, 4) = new TokenSegment(start, span.Length);
                return 5;
            }

            return 0;
        }


        public unsafe static int Tokenize_Unroll_Unsafe_Goto(ReadOnlySpan<byte> token, TokenSegment* pSegments)
        {
            int start;
            var span = token;
            int last = span.LastIndexOf(ByteDot);
            int end = span.IndexOf(ByteDot);
            if (end < 0)
            {
                goto Malformed;
            }

            *pSegments = new TokenSegment(0, end);
            start = end + 1;
            span = token.Slice(start);
            end = span.IndexOf(ByteDot);
            if (end < 0)
            {
                goto Malformed;
            }

            *(pSegments + 1) = new TokenSegment(start, end);
            start += end + 1;
            if (last == start - 1)
            {
                *(pSegments + 2) = new TokenSegment(last + 1, token.Length - last - 1);
                return 3;
            }

            span = token.Slice(start);
            end = span.IndexOf(ByteDot);
            if (end < 0)
            {
                goto Malformed;
            }

            *(pSegments + 2) = new TokenSegment(start, end);
            start += end + 1;
            span = token.Slice(start);

            end = span.IndexOf(ByteDot);
            if (end < 0)
            {
                goto Malformed;
            }

            *(pSegments + 3) = new TokenSegment(start, end);
            start += end + 1;
            if (last == start - 1)
            {
                *(pSegments + 4) = new TokenSegment(last + 1, token.Length - last - 1);
                return 5;
            }

        Malformed:
            return 0;
        }

    }
}
