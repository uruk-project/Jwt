using System;

namespace JsonWebToken.Analyzers
{
    internal static class ByteArrayExtensions
    {
        public static byte[] Trim(this byte[] value)
        {
            if (value.Length == 0)
            {
                return value;
            }

            int i = value.Length - 1;
            while (i >= 0 && value[i] == 0)
                --i;

            if (i == 0)
            {
                return Array.Empty<byte>();
            }

            byte[] tmp = new byte[i + 1];
            Array.Copy(value, tmp, i + 1);

            return tmp;
        }
    }
}
