// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.ComponentModel;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Provides helper methods for UNIX-like time.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static class EpochTime
    {
        internal static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
        private static readonly DateTime MaxUnixTime = UnixEpoch.AddSafe(TimeSpan.MaxValue.Ticks).ToUniversalTime();

        /// <summary>
        /// Per JWT spec:
        /// Gets the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the desired date/time.
        /// </summary>
        /// <param name="datetime">The DateTime to convert to seconds.</param>
        /// <remarks>if dateTimeUtc less than UnixEpoch, return 0</remarks>
        /// <returns>the number of seconds since Unix Epoch.</returns>
        public static long ToEpochTime(this DateTime datetime)
        {
            if (datetime.Kind != DateTimeKind.Utc)
            {
                datetime = datetime.ToUniversalTime();
            }

            if (datetime <= UnixEpoch)
            {
                return 0;
            }

            return (long)(datetime - UnixEpoch).TotalSeconds;
        }

        /// <summary>
        /// Creates a DateTime from epoch time.
        /// </summary>
        /// <param name="secondsSinceUnixEpoch">Number of seconds.</param>
        /// <returns>The DateTime in UTC.</returns>
        public static DateTime ToDateTime(long secondsSinceUnixEpoch)
        {
            if (secondsSinceUnixEpoch <= 0)
            {
                return UnixEpoch;
            }

            if (secondsSinceUnixEpoch > TimeSpan.MaxValue.TotalSeconds)
            {
                return MaxUnixTime;
            }

            return UnixEpoch.AddSafe(secondsSinceUnixEpoch * TimeSpan.TicksPerSecond).ToUniversalTime();
        }

        /// <summary>
        /// Creates a DateTime from epoch time.
        /// </summary>
        /// <param name="secondsSinceUnixEpoch">Number of seconds.</param>
        /// <returns>The DateTime in UTC.</returns>
        public static DateTime? ToDateTime(long? secondsSinceUnixEpoch)
        {
            if (!secondsSinceUnixEpoch.HasValue)
            {
                return null;
            }

            return ToDateTime(secondsSinceUnixEpoch.Value);
        }
    }
}
