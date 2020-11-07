using System.Diagnostics;
using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// Defines an abstract class for representing a JWT.
    /// </summary>
    [DebuggerDisplay("{DebuggerDisplay(),nq}")]
    public abstract class JwtDescriptorX
    {
        private Jwk? _key;
        private JwtHeaderX _header;

        /// <summary>
        /// Initializes a new instance of <see cref="JwtDescriptor"/>.
        /// </summary>
        protected JwtDescriptorX()
        {
            _header = new JwtHeaderX();
        }

        /// <summary>
        /// Gets the parameters header.
        /// </summary>
        public JwtHeaderX Header
        {
            get => _header;
            set
            {
                if (value is null)
                {
                    ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
                }

                _header.CopyTo(value);
                _header = value;
            }
        }

        /// <summary>
        /// Gets the <see cref="Jwk"/> used.
        /// </summary>
        protected Jwk Key
        {
            get => _key ?? Jwk.Empty;
            set
            {
                if (value is null)
                {
                    ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
                }

                _key = value;
                if (value.Kid != null)
                {
                    Header.Add(HeaderParameters.Kid, value.Kid);
                }

                OnKeyChanged(value);
            }
        }

        /// <summary>
        /// Called when the key is set.
        /// </summary>
        /// <param name="key"></param>
        protected abstract void OnKeyChanged(Jwk? key);

        /// <summary>
        /// Encodes the current <see cref="JwtDescriptor"/> into it <see cref="string"/> representation.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public abstract void Encode(EncodingContext context);

        /// <summary>
        /// Validates the current <see cref="JwtDescriptor"/>.
        /// </summary>
        public virtual void Validate()
        {
        }

        /// <summary>
        /// Validates the presence and the type of a required header.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="type"></param>
        protected void CheckRequiredHeader(string utf8Name, JsonValueKind type)
        {
            if (!Header.TryGetValue(utf8Name, out var tokenType))
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderIsRequired(utf8Name);
            }

            if (tokenType.Type != type)
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderMustBeOfType(utf8Name, type);
            }
        }

        /// <summary>
        /// Validates the presence and the type of a required header.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="types"></param>
        protected void CheckRequiredHeader(string utf8Name, JsonValueKind[] types)
        {
            if (!Header.TryGetValue(utf8Name, out var tokenType))
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderIsRequired(utf8Name);
            }

            for (int i = 0; i < types.Length; i++)
            {
                if (tokenType.Type == types[i])
                {
                    return;
                }
            }

            ThrowHelper.ThrowJwtDescriptorException_HeaderMustBeOfType(utf8Name, types);
        }
    }
}