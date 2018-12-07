// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// Defines an encrypted JWT with a <see cref="JwsDescriptor"/> payload.
    /// </summary>
    public sealed class JweDescriptor : JweDescriptor<JwsDescriptor>
    {
        /// <summary>
        /// Initializes an new instance of <see cref="JweDescriptor{TDescriptor}"/>.
        /// </summary>
        public JweDescriptor()
            : base()
        {
            Header[HeaderParameters.Cty] = ContentTypeValues.Jwt;
        }

        /// <summary>
        /// Initializes an new instance of <see cref="JweDescriptor{TDescriptor}"/>.
        /// </summary>
        /// <param name="header"></param>
        /// <param name="payload"></param>
        public JweDescriptor(IDictionary<string, object> header, JwsDescriptor payload)
            : base(header, payload)
        {
            Header[HeaderParameters.Cty] = ContentTypeValues.Jwt;
        }

        /// <summary>
        /// Initializes an new instance of <see cref="JweDescriptor{TDescriptor}"/>.
        /// </summary>
        /// <param name="payload"></param>
        public JweDescriptor(JwsDescriptor payload)
            : base(new Dictionary<string, object>(), payload)
        {
            Header[HeaderParameters.Cty] = ContentTypeValues.Jwt;
        }
    }
}
