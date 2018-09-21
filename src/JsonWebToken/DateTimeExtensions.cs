using System;

namespace JsonWebToken
{
    /// <summary>
    /// Helper class for adding DateTimes and Timespans.
    /// </summary>
    internal static class DateTimeExtensions
    {
        private static readonly DateTime MaxValueUtc = new DateTime(DateTime.MaxValue.Ticks, DateTimeKind.Utc);
        private static readonly DateTime MaxValueLocal = new DateTime(DateTime.MaxValue.Ticks, DateTimeKind.Local);
        private static readonly DateTime MinValueUtc = new DateTime(DateTime.MinValue.Ticks, DateTimeKind.Utc);
        private static readonly DateTime MinValueLocal = new DateTime(DateTime.MinValue.Ticks, DateTimeKind.Local);

        private static readonly long MaxValue = DateTime.MaxValue.Ticks;
        private static readonly long MinValue = DateTime.MinValue.Ticks;

        /// <summary>
        /// Add a DateTime and a Ticks.
        /// The maximum time is DateTime.MaxTime.  It is not an error if time + ticks > MaxTime.
        /// Just return MaxTime.
        /// </summary>
        /// <param name="time">Initial <see cref="DateTime"/> value.</param>
        /// <param name="ticks"><see cref="TimeSpan.Ticks"/> to add.</param>
        /// <returns><see cref="DateTime"/> as the sum of time and timespan.</returns>
        public static DateTime AddSafe(this DateTime time, long ticks)
        {
            if (ticks == 0)
            {
                return time;
            }

            if (ticks > 0 && EpochTime.MaxValue - time.Ticks <= ticks)
            {
                if (time.Kind == DateTimeKind.Local)
                {
                    return MaxValueLocal;
                }

                return MaxValueUtc;
            }

            if (ticks < 0 && EpochTime.MinValue - time.Ticks >= ticks)
            {
                if (time.Kind == DateTimeKind.Local)
                {
                    return MinValueLocal;
                }

                return MinValueUtc;
            }

            return time.AddTicks(ticks);
        }
    }
}
