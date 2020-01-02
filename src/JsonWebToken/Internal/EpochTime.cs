// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Provides helper methods for UNIX-like time.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static class EpochTime
    {
        private const long UnixEpochTicks = 621355968000000000;
        private const long MaxValue = 9223372036854775807;
        private static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        private static readonly DateTime MaxValueUtc = new DateTime(DateTime.MaxValue.Ticks, DateTimeKind.Utc);

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

            var ticks = datetime.Ticks;
            if (ticks <= UnixEpochTicks)
            {
                return 0;
            }

            return (ticks - UnixEpochTicks) / 10000000;
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

            if (MaxValue - UnixEpochTicks <= secondsSinceUnixEpoch)
            {
                return MaxValueUtc;
            }

            return UnixEpoch.AddSeconds(secondsSinceUnixEpoch);
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

        /// <summary>
        /// Gets the current date and time on this computer expressed as the UTC time, in the Unix epoch time format (total of seconds since the 01/01/1970). 
        /// </summary>
        public static long UtcNow
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => (DateTime.UtcNow.Ticks - UnixEpochTicks) / 10000000;
        }
    }
}
