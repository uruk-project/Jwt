// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Text;
using System.Text.Json;

namespace JsonWebToken
{
    public sealed class Address
    {
        public string? Formatted { get; set; }

        public string? StreetAddress { get; set; }

        public string? Locality { get; set; }

        public string? Region { get; set; }

        public string? PostalCode { get; set; }

        public string? Country { get; set; }

        public static Address FromJson(ReadOnlySpan<byte> json)
        {
            Utf8JsonReader reader = new Utf8JsonReader(json, true, default);

            var address = new Address();
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.EndObject:
                        return address;

                    case JsonTokenType.PropertyName:
                        var propertyName = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan;

                        reader.Read();
                        switch (reader.TokenType)
                        {
                            case JsonTokenType.String:
                                if (propertyName.SequenceEqual(OAuth2Claims.Formatted.EncodedUtf8Bytes))
                                {
                                    address.Formatted = reader.GetString();
                                }
                                else if (propertyName.SequenceEqual(OAuth2Claims.StreetAddress.EncodedUtf8Bytes))
                                {
                                    address.StreetAddress = reader.GetString();
                                }
                                else if (propertyName.SequenceEqual(OAuth2Claims.Locality.EncodedUtf8Bytes))
                                {
                                    address.Locality = reader.GetString();
                                }
                                else if (propertyName.SequenceEqual(OAuth2Claims.Region.EncodedUtf8Bytes))
                                {
                                    address.Region = reader.GetString();
                                }
                                else if (propertyName.SequenceEqual(OAuth2Claims.PostalCode.EncodedUtf8Bytes))
                                {
                                    address.PostalCode = reader.GetString();
                                }
                                else if (propertyName.SequenceEqual(OAuth2Claims.Country.EncodedUtf8Bytes))
                                {
                                    address.Country = reader.GetString();
                                }
                                break;
                            case JsonTokenType.StartArray:
                                JsonParser.ConsumeJsonArray(ref reader);
                                break;
                            case JsonTokenType.StartObject:
                                JsonParser.ConsumeJsonObject(ref reader);
                                break;
                        }
                        break;
                    default:
                        ThrowHelper.ThrowFormatException_MalformedJson();
                        break;
                }
            }

            ThrowHelper.ThrowFormatException_MalformedJson();
            return null;
        }

        public static Address FromJson(string json)
        {
            return FromJson(Utf8.GetBytes(json));
        }

        public override string ToString()
        {
            return Utf8.GetString(Serialize());
        }

        public byte[] Serialize()
        {
            using var bufferWriter = new PooledByteBufferWriter();
            using (var writer = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { SkipValidation = true }))
            {
                writer.WriteStartObject();
                WriteTo(writer);
                writer.WriteEndObject();
            }

            var input = bufferWriter.WrittenSpan;
            return input.ToArray();
        }

        internal void WriteTo(Utf8JsonWriter writer)
        {
            if (Formatted != null)
            {
                writer.WriteString(OAuth2Claims.Formatted, Formatted);
            }

            if (StreetAddress != null)
            {
                writer.WriteString(OAuth2Claims.StreetAddress, StreetAddress);
            }

            if (Locality != null)
            {
                writer.WriteString(OAuth2Claims.Locality, Locality);
            }

            if (Region != null)
            {
                writer.WriteString(OAuth2Claims.Region, Region);
            }

            if (PostalCode != null)
            {
                writer.WriteString(OAuth2Claims.PostalCode, PostalCode);
            }

            if (Country != null)
            {
                writer.WriteString(OAuth2Claims.Country, Country);
            }
        }
    }
}
