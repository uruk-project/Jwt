using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace JsonWebToken
{
    [StructLayout(LayoutKind.Sequential)]
    internal readonly struct JwtObjectRow
    {
        internal const int Size = 12;
        private readonly int _location;
        private readonly int _propertyLength;
        private readonly int _endPosition;

        /// <summary>
        /// Index into the payload
        /// </summary>
        internal int StartPosition => _location & 0x0FFFFFFF;

        internal JsonTokenType TokenType => (JsonTokenType)(unchecked((uint)_location) >> 28);

        public int Length => _propertyLength;
        public int EndPosition => _endPosition;

        internal JwtObjectRow(JsonTokenType jsonTokenType, int location, int propertyLength, int endPosition)
        {
            Debug.Assert(location >= 0);
            Debug.Assert(location < 1 << 28);

            _location = location | ((int)jsonTokenType << 28);
            _propertyLength = propertyLength;
            _endPosition = endPosition;
        }
    }
}