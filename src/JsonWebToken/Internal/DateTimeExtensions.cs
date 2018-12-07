// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken.Internal
{
    internal static class DateTimeExtensions
    {
        private static readonly long MaxValue = TimeSpan.MaxValue.Ticks;
        private static readonly long MinValue = EpochTime.UnixEpoch.Ticks;

        private static readonly DateTime MaxValueUtc = new DateTime(DateTime.MaxValue.Ticks, DateTimeKind.Utc);
        private static readonly DateTime MaxValueLocal = new DateTime(DateTime.MaxValue.Ticks, DateTimeKind.Local);
        private static readonly DateTime MinValueUtc = new DateTime(DateTime.MinValue.Ticks, DateTimeKind.Utc);
        private static readonly DateTime MinValueLocal = new DateTime(DateTime.MinValue.Ticks, DateTimeKind.Local);

        public static DateTime AddSafe(this DateTime time, long ticks)
        {
            if (ticks == 0)
            {
                return time;
            }

            if (ticks > 0 && MaxValue - time.Ticks <= ticks)
            {
                if (time.Kind == DateTimeKind.Local)
                {
                    return MaxValueLocal;
                }

                return MaxValueUtc;
            }

            if (ticks < 0 && MinValue - time.Ticks >= ticks)
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
