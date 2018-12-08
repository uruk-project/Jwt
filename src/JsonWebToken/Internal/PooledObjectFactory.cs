// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

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
