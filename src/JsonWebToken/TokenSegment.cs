// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    public readonly struct TokenSegment : IEquatable<TokenSegment>
    {
        public readonly int Start;
        public readonly int Length;

        public TokenSegment(int start, int length)
        {
            Start = start;
            Length = length;
        }

        public override bool Equals(object obj)
        {
            return obj is TokenSegment segment ? Equals(segment) : false;
        }

        public bool Equals(TokenSegment other)
        {
            return Start == other.Start && Length == other.Length;
        }

        public override int GetHashCode()
        {
            return Start;
        }

        public override string ToString()
        {
            return $"Segment({Start}:{Length})";
        }

        public bool IsEmpty => Length == 0;
    }
}