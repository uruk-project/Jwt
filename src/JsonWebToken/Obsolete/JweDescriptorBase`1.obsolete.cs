// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.ComponentModel;

namespace JsonWebToken
{
    public abstract partial class JweDescriptorBase<TDescriptor> 
    {
        /// <summary>Gets or sets the algorithm header.</summary>
        [Obsolete("This property is obsolete. Use the constructor for passing this value, or the property Alg instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public KeyManagementAlgorithm? Algorithm
        {
            get => throw new NotImplementedException();
            set => throw new NotImplementedException();
        }

        /// <summary>Gets or sets the encryption algorithm.</summary>
        [Obsolete("This property is obsolete. Use the constructor for passing this value, or the property Enc instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public EncryptionAlgorithm? EncryptionAlgorithm
        {
            get => throw new NotImplementedException();
            set => throw new NotImplementedException();
        }

        /// <summary>Gets or sets the compression algorithm.</summary>
        [Obsolete("This property is obsolete. Use the constructor for passing this value, or the property Zip instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public CompressionAlgorithm? CompressionAlgorithm
        {
            get => throw new NotImplementedException();
            set => throw new NotImplementedException();
        }
    }
}
