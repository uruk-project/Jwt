using System;

namespace JsonWebTokens
{
    /// <summary>
    /// Returns the absolute DateTime or the Seconds since Unix Epoch, where Epoch is UTC 1970-01-01T0:0:0Z.
    /// </summary>
    public static class EpochTime
    {
        /// <summary>
        /// DateTime as UTC for UnixEpoch
        /// </summary>
        public static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
        public static readonly long MaxValue = GetIntDate(DateTime.MaxValue);
        public static readonly long MinValue = GetIntDate(UnixEpoch);

        /// <summary>
        /// Per JWT spec:
        /// Gets the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the desired date/time.
        /// </summary>
        /// <param name="datetime">The DateTime to convert to seconds.</param>
        /// <remarks>if dateTimeUtc less than UnixEpoch, return 0</remarks>
        /// <returns>the number of seconds since Unix Epoch.</returns>
        public static long GetIntDate(DateTime? dateTime)
        {
            if(!dateTime.HasValue)
            {
                return 0;
            }

            DateTime dateTimeUtc = dateTime.Value;
            if (dateTimeUtc.Kind != DateTimeKind.Utc)
            {
                dateTimeUtc = dateTimeUtc.ToUniversalTime();
            }

            if (dateTimeUtc.ToUniversalTime() <= UnixEpoch)
            {
                return 0;
            }

            return (long)(dateTimeUtc - UnixEpoch).TotalSeconds;
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
                return DateTimeUtil.Add(UnixEpoch, TimeSpan.MaxValue).ToUniversalTime();
            }

            return DateTimeUtil.Add(UnixEpoch, TimeSpan.FromSeconds(secondsSinceUnixEpoch)).ToUniversalTime();
        }
    }
}
