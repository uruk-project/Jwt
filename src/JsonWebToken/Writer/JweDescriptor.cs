// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>Defines an encrypted JWT with a <see cref="JwsDescriptor"/> payload.</summary>
    public sealed partial class JweDescriptor : JweDescriptorBase<JwsDescriptor>
    {
        private JwsDescriptor? _payload;

        /// <summary>Initializes a new instance of the <see cref="JweDescriptor"/> class.</summary>
        public JweDescriptor(Jwk encryptionKey, KeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null, string? typ = null, string? cty = Constants.Jwt)
            : base(encryptionKey, alg, enc, zip, typ, cty)
        {
        }

        /// <inheritdoc/>
        public override JwsDescriptor Payload
        {
            get
            {
                if (_payload is null)
                {
                    ThrowHelper.ThrowInvalidOperationException_NotInitialized(ExceptionArgument.payload);
                }

                return _payload;
            }

            set
            {
                if (value is null)
                {
                    ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
                }

                _payload = value;
            }
        }

        /// <inheritdoc/>
        public override void Validate()
        {
            if (_payload is not null)
            {
                _payload.Validate();
            }
        }
    }
}
