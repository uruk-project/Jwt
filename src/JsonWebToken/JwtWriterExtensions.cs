// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Text;

namespace JsonWebToken
{
    /// <summary>
    /// Providers extensions methods for <see cref="JwtWriter"/>.
    /// </summary>
    public static class JwtWriterExtensions
    {
        /// <summary>
        /// Writes a JWT in its compact serialization format and returns it a string.
        /// </summary>
        /// <param name="writer"></param>
        /// <param name="descriptor">The descriptor of the JWT.</param>
        /// <returns>The <see cref="string"/> retpresention of the JWT.</returns>
        public static string WriteTokenString(this JwtWriter writer, JwtDescriptor descriptor)
        {
            if (writer == null)
            {
                throw new ArgumentNullException(nameof(writer));
            }

            return Encoding.UTF8.GetString(writer.WriteToken(descriptor));
        }
    }
}
