// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>Represents a segment of token.</summary>
    internal readonly struct TokenSegment
    {
        /// <summary>The start of the segment.</summary>
        public readonly int Start;

        /// <summary>The end of the segment.</summary>
        public readonly int Length;

        /// <summary>Initializes a new instance of <see cref="TokenSegment"/>.</summary>
        /// <param name="start"></param>
        /// <param name="length"></param>
        public TokenSegment(int start, int length)
        {
            Start = start;
            Length = length;
        }

        /// <inheritsdoc />
        public override string ToString() => $"Segment({Start}:{Length})";

        /// <summary>Gets wether the segment is empty.</summary>
        public bool IsEmpty => Length == 0;
    }
}