#if !NETCOREAPP2_1
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace JsonWebToken
{
    public static class EncodingHelper
    {
        public static unsafe void GetUtf8Bytes(string input, Span<byte> output)
        {
            GetUtf8Bytes(input.AsSpan(), output);
        }

        public static unsafe void GetUtf8Bytes(ReadOnlySpan<char> input, Span<byte> output)
        {
            fixed (char* inputPtr = &MemoryMarshal.GetReference(input))
            fixed (byte* outputPtr = &MemoryMarshal.GetReference(output))
            {
                Encoding.UTF8.GetBytes(inputPtr, input.Length, outputPtr, output.Length);
            }
        }

        public static unsafe void GetAsciiBytes(string input, Span<byte> output)
        {
            GetAsciiBytes(input.AsSpan(), output);
        }

        public static unsafe void GetAsciiBytes(ReadOnlySpan<char> input, Span<byte> output)
        {
            fixed (char* inputPtr = &MemoryMarshal.GetReference(input))
            fixed (byte* outputPtr = &MemoryMarshal.GetReference(output))
            {
                Encoding.ASCII.GetBytes(inputPtr, input.Length, outputPtr, output.Length);
            }
        }
    }
}
#endif