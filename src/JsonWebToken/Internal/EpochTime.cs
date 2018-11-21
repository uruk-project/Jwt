// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.ComponentModel;

namespace JsonWebToken.Internal
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static class EpochTime
    {
        public static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
        public static readonly long MaxValue = TimeSpan.MaxValue.Ticks;
        public static readonly long MinValue = UnixEpoch.Ticks;

        /// <summary>
        /// Per JWT spec:
        /// Gets the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the desired date/time.
        /// </summary>
        /// <param name="datetime">The DateTime to convert to seconds.</param>
        /// <remarks>if dateTimeUtc less than UnixEpoch, return 0</remarks>
        /// <returns>the number of seconds since Unix Epoch.</returns>
        public static long ToEpochTime(this DateTime? dateTime)
        {
            if (!dateTime.HasValue)
            {
                return 0;
            }

            return dateTime.Value.ToEpochTime();
        }

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
                return UnixEpoch.AddSafe(TimeSpan.MaxValue.Ticks).ToUniversalTime();
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
