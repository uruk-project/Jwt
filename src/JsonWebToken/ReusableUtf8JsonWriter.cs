// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.Text.Json;

namespace JsonWebToken
{
    // from https://github.com/aspnet/AspNetCore/blob/master/src/SignalR/common/Shared/ReusableUtf8JsonWriter.cs
    internal sealed class ReusableUtf8JsonWriter
    {
        [ThreadStatic]
        private static ReusableUtf8JsonWriter _cachedInstance;

        private readonly Utf8JsonWriter _writer;

#if DEBUG
        private bool _inUse;
#endif

        public ReusableUtf8JsonWriter(IBufferWriter<byte> stream)
        {
            _writer = new Utf8JsonWriter(stream, new JsonWriterOptions() { SkipValidation = true });
        }

        public static ReusableUtf8JsonWriter Get(IBufferWriter<byte> stream)
        {
            var writer = _cachedInstance;
            if (writer == null)
            {
                writer = new ReusableUtf8JsonWriter(stream);
            }

            // Taken off the thread static
            _cachedInstance = null;
#if DEBUG
            if (writer._inUse)
            {
                throw new InvalidOperationException("The writer wasn't returned!");
            }

            writer._inUse = true;
#endif
            writer._writer.Reset(stream);
            return writer;
        }

        public static void Return(ReusableUtf8JsonWriter writer)
        {
            _cachedInstance = writer;

            writer._writer.Reset();

#if DEBUG
            writer._inUse = false;
#endif
        }

        public Utf8JsonWriter GetJsonWriter()
        {
            return _writer;
        }
    }
}