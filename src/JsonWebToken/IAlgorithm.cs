// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken
{
    /// <summary>
    /// Represents a cyrptographic algorithm.
    /// </summary>
    public interface IAlgorithm
    {
        /// <summary>
        /// Gets the UTF8 byte array of the name of the algorithm.
        /// </summary>
        public byte[] Utf8Name { get; }

        /// <summary>
        /// Gets the name of the algorithm.
        /// </summary>
        public string Name { get; }
    }
}