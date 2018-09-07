using System;

namespace JsonWebToken
{
    public sealed class JwtDescriptorException : Exception
    {
        public JwtDescriptorException(string message)
            : base(message)
        {
        }
    }
}