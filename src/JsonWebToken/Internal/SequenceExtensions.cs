using System;
using System.Buffers;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Provides extension methods for <see cref="ReadOnlySequence{T}"/>.
    /// </summary>
    internal static class SequenceExtensions
    {
        /// <summary>
        /// Reports the first occurrence of the specified <paramref name="value"/>.
        /// </summary>
        /// <param name="sequence"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public static long IndexOf(this ReadOnlySequence<byte> sequence, byte value)
        {
            SequencePosition position = sequence.Start;
            int totalIndex = 0;
            while (sequence.TryGet(ref position, out ReadOnlyMemory<byte> memory))
            {
                var index = memory.Span.IndexOf(value);
                if (index != -1)
                {
                    return index + totalIndex;
                }

                totalIndex += memory.Length;
            }

            return -1;
        }
    }
}
