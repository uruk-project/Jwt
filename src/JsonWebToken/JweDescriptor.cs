// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// Defines an encrypted JWT with a <see cref="JwsDescriptor"/> payload.
    /// </summary>
    public sealed class JweDescriptor : JweDescriptor<JwsDescriptor>
    {
        private static readonly JwtProperty Cty = new JwtProperty(HeaderParameters.CtyUtf8, ContentTypeValues.Jwt);

        /// <summary>
        /// Initializes an new instance of <see cref="JweDescriptor{TDescriptor}"/>.
        /// </summary>
        public JweDescriptor()
            : base()
        {
            Header.Add(Cty);
        }

        /// <summary>
        /// Initializes an new instance of <see cref="JweDescriptor{TDescriptor}"/>.
        /// </summary>
        /// <param name="header"></param>
        /// <param name="payload"></param>
        public JweDescriptor(JwtObject header, JwsDescriptor payload)
            : base(header, payload)
        {
            Header.Add(Cty);
        }

        /// <summary>
        /// Initializes an new instance of <see cref="JweDescriptor{TDescriptor}"/>.
        /// </summary>
        /// <param name="payload"></param>
        public JweDescriptor(JwsDescriptor payload)
            : base(new JwtObject(), payload)
        {
            Header.Add(Cty);
        }

        /// <inheritsdoc />
        public override void Validate()
        {
            base.Validate();

            ValidateHeader(HeaderParameters.AlgUtf8, JwtTokenType.Utf8String);
            ValidateHeader(HeaderParameters.EncUtf8, JwtTokenType.Utf8String);
        }
    }
}
