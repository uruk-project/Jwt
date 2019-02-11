// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Buffers;
using System.Text;
using System.Text.Json;

namespace JsonWebToken
{
    public class Address
    {
        public string Formatted { get; set; }

        public string StreetAddress { get; set; }

        public string Locality { get; set; }

        public string Region { get; set; }

        public string PostalCode { get; set; }

        public string Country { get; set; }

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
                                if (propertyName.SequenceEqual(OidcClaims.FormattedUtf8))
                                {
                                    address.Formatted = reader.GetString();
                                }
                                else if (propertyName.SequenceEqual(OidcClaims.StreetAddressUtf8))
                                {
                                    address.StreetAddress = reader.GetString();
                                }
                                else if (propertyName.SequenceEqual(OidcClaims.LocalityUtf8))
                                {
                                    address.Locality = reader.GetString();
                                }
                                else if (propertyName.SequenceEqual(OidcClaims.RegionUtf8))
                                {
                                    address.Region = reader.GetString();
                                }
                                else if (propertyName.SequenceEqual(OidcClaims.PostalCodeUtf8))
                                {
                                    address.PostalCode = reader.GetString();
                                }
                                else if (propertyName.SequenceEqual(OidcClaims.CountryUtf8))
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
                        JwtThrowHelper.FormatMalformedJson();
                        break;
                }
            }

            JwtThrowHelper.FormatMalformedJson();
            return null;
        }

        public static Address FromJson(string json)
        {
            return FromJson(Encoding.UTF8.GetBytes(json));
        }

        public override string ToString()
        {
            return Encoding.UTF8.GetString(Serialize());
        }

        public byte[] Serialize()
        {
            using (var bufferWriter = new ArrayBufferWriter<byte>())
            {
                Utf8JsonWriter writer = new Utf8JsonWriter(bufferWriter, new JsonWriterState(new JsonWriterOptions { Indented = true }));

                writer.WriteStartObject();
                WriteTo(ref writer);
                writer.WriteEndObject();
                writer.Flush();

                var input = bufferWriter.WrittenSpan;
                return input.ToArray();
            }
        }

        internal void WriteTo(ref Utf8JsonWriter writer)
        {
            if (Formatted != null)
            {
                writer.WriteString(OidcClaims.FormattedUtf8, Formatted);
            }

            if (StreetAddress != null)
            {
                writer.WriteString(OidcClaims.StreetAddressUtf8, StreetAddress);
            }

            if (Locality != null)
            {
                writer.WriteString(OidcClaims.LocalityUtf8, Locality);
            }

            if (Region != null)
            {
                writer.WriteString(OidcClaims.RegionUtf8, Region);
            }

            if (PostalCode != null)
            {
                writer.WriteString(OidcClaims.PostalCodeUtf8, PostalCode);
            }

            if (Country != null)
            {
                writer.WriteString(OidcClaims.CountryUtf8, Country);
            }
        }
    }
}
