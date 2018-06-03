using System;

namespace JsonWebTokens
{
    public class JwtDescriptorException : Exception
    {
        public JwtDescriptorException(string message)
            : base(message)
        {
        }
    }
}