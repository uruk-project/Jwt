// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.ComponentModel;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Represent a factory of a poolable <typeparamref name="T"/>.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public abstract class PooledObjectFactory<T>
    {
        /// <summary>
        /// Creates the poolabled <typeparamref name="T"/>.
        /// </summary>
        /// <returns></returns>
        public abstract T Create();
    }
}
