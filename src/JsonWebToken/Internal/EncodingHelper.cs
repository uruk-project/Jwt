#if !NETCOREAPP2_1
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace JsonWebToken
{
    public static class EncodingHelper
    {
        public static unsafe string GetUtf8String(Span<byte> input)
        {
            fixed (byte* ptr = input)
            {
                return Encoding.UTF8.GetString(ptr, input.Length);
            }
        }

        public static void GetUtf8Bytes(string input, Span<byte> output)
        {
            GetUtf8Bytes(input.AsSpan(), output);
        }

        public static unsafe void GetUtf8Bytes(ReadOnlySpan<char> input, Span<byte> output)
        {
            fixed (char* inputPtr = input)
            fixed (byte* outputPtr = output)
            {
                Encoding.UTF8.GetBytes(inputPtr, input.Length, outputPtr, output.Length);
            }
        }

        public static void GetAsciiBytes(string input, Span<byte> output)
        {
            GetAsciiBytes(input.AsSpan(), output);
        }

        public static unsafe void GetAsciiBytes(ReadOnlySpan<char> input, Span<byte> output)
        {
            fixed (char* inputPtr = input)
            fixed (byte* outputPtr = output)
            {
                Encoding.ASCII.GetBytes(inputPtr, input.Length, outputPtr, output.Length);
            }
        }
    }
}
#endif