using System;
using System.Buffers;

namespace gfoidl.Base64
{
    /// <summary>
    /// Base64 encoding / decoding.
    /// </summary>
    public interface IBase64
    {
        /// <summary>
        /// Gets the length of the encoded data.
        /// </summary>
        /// <param name="sourceLength">The length of the data.</param>
        /// <returns>The base64 encoded length of <paramref name="sourceLength" />.</returns>
        int GetEncodedLength(int sourceLength);
        //---------------------------------------------------------------------
        /// <summary>
        /// Gets the length of the decoded data.
        /// </summary>
        /// <param name="encoded">The encoded data.</param>
        /// <returns>The base64 decoded length of <paramref name="encoded" />. Any padding is handled.</returns>
        int GetDecodedLength(ReadOnlySpan<byte> encoded);
        //---------------------------------------------------------------------
        /// <summary>
        /// Gets the length of the decoded data.
        /// </summary>
        /// <param name="encoded">The encoded data.</param>
        /// <returns>The base64 decoded length of <paramref name="encoded" />. Any padding is handled.</returns>
        int GetDecodedLength(ReadOnlySpan<char> encoded);
        //---------------------------------------------------------------------
        /// <summary>
        /// Base64 encodes <paramref name="data" />.
        /// </summary>
        /// <param name="data">The data to be base64 encoded.</param>
        /// <param name="encoded">The base64 encoded data.</param>
        /// <param name="consumed">
        /// The number of input bytes consumed during the operation. This can be used to slice the input for 
        /// subsequent calls, if necessary.
        /// </param>
        /// <param name="written">
        /// The number of bytes written into the output span. This can be used to slice the output for 
        /// subsequent calls, if necessary.
        /// </param>
        /// <param name="isFinalBlock">
        /// <c>true</c> (default) when the input span contains the entire data to decode.
        /// Set to <c>false</c> only if it is known that the input span contains partial data with more data to follow.
        /// </param>
        /// <returns>
        /// It returns the OperationStatus enum values:
        /// <list type="bullet">
        /// <item><description>Done - on successful processing of the entire input span</description></item>
        /// <item><description>DestinationTooSmall - if there is not enough space in the output span to fit the decoded input</description></item>
        /// <item><description>
        /// NeedMoreData - only if isFinalBlock is false and the input is not a multiple of 4, otherwise the partial input 
        /// would be considered as InvalidData
        /// </description></item>
        /// <item><description>
        /// InvalidData - if the input contains bytes outside of the expected base64 range, or if it contains invalid/more 
        /// than two padding characters, or if the input is incomplete (i.e. not a multiple of 4) and isFinalBlock is true.
        /// </description></item>
        /// </list>
        /// </returns>
        OperationStatus Encode(
            ReadOnlySpan<byte> data,
            Span<byte>         encoded,
            out                int consumed,
            out                int written,
            bool               isFinalBlock = true);
        //---------------------------------------------------------------------
        /// <summary>
        /// Base64 encodes <paramref name="data" />.
        /// </summary>
        /// <param name="data">The data to be base64 encoded.</param>
        /// <param name="encoded">The base64 encoded data.</param>
        /// <param name="consumed">
        /// The number of input bytes consumed during the operation. This can be used to slice the input for 
        /// subsequent calls, if necessary.
        /// </param>
        /// <param name="written">
        /// The number of chars written into the output span. This can be used to slice the output for 
        /// subsequent calls, if necessary.
        /// </param>
        /// <param name="isFinalBlock">
        /// <c>true</c> (default) when the input span contains the entire data to decode.
        /// Set to <c>false</c> only if it is known that the input span contains partial data with more data to follow.
        /// </param>
        /// <returns>
        /// It returns the OperationStatus enum values:
        /// <list type="bullet">
        /// <item><description>Done - on successful processing of the entire input span</description></item>
        /// <item><description>DestinationTooSmall - if there is not enough space in the output span to fit the decoded input</description></item>
        /// <item><description>
        /// NeedMoreData - only if isFinalBlock is false and the input is not a multiple of 4, otherwise the partial input 
        /// would be considered as InvalidData
        /// </description></item>
        /// <item><description>
        /// InvalidData - if the input contains bytes outside of the expected base64 range, or if it contains invalid/more 
        /// than two padding characters, or if the input is incomplete (i.e. not a multiple of 4) and isFinalBlock is true.
        /// </description></item>
        /// </list>
        /// </returns>
        OperationStatus Encode(
            ReadOnlySpan<byte> data,
            Span<char>         encoded,
            out                int consumed,
            out                int written,
            bool               isFinalBlock = true);
        //---------------------------------------------------------------------
        /// <summary>
        /// Base64 decodes <paramref name="encoded" />.
        /// </summary>
        /// <param name="encoded">The base64 encoded data.</param>
        /// <param name="data">The base64 decoded data.</param>
        /// <param name="consumed">
        /// The number of input bytes consumed during the operation. This can be used to slice the input for 
        /// subsequent calls, if necessary.
        /// </param>
        /// <param name="written">
        /// The number of bytes written into the output span. This can be used to slice the output for 
        /// subsequent calls, if necessary.
        /// </param>
        /// <param name="isFinalBlock">
        /// <c>true</c> (default) when the input span contains the entire data to decode.
        /// Set to <c>false</c> only if it is known that the input span contains partial data with more data to follow.
        /// </param>
        /// <returns>
        /// It returns the OperationStatus enum values:
        /// <list type="bullet">
        /// <item><description>Done - on successful processing of the entire input span</description></item>
        /// <item><description>DestinationTooSmall - if there is not enough space in the output span to fit the decoded input</description></item>
        /// <item><description>
        /// NeedMoreData - only if isFinalBlock is false and the input is not a multiple of 4, otherwise the partial input 
        /// would be considered as InvalidData
        /// </description></item>
        /// <item><description>
        /// InvalidData - if the input contains bytes outside of the expected base64 range, or if it contains invalid/more 
        /// than two padding characters, or if the input is incomplete (i.e. not a multiple of 4) and isFinalBlock is true.
        /// </description></item>
        /// </list>
        /// </returns>
        OperationStatus Decode(
            ReadOnlySpan<byte> encoded,
            Span<byte>         data,
            out                int consumed,
            out                int written,
            bool               isFinalBlock = true);
        //---------------------------------------------------------------------
        /// <summary>
        /// Base64 decodes <paramref name="encoded" />.
        /// </summary>
        /// <param name="encoded">The base64 encoded data.</param>
        /// <param name="data">The base64 decoded data.</param>
        /// <param name="consumed">
        /// The number of input chars consumed during the operation. This can be used to slice the input for 
        /// subsequent calls, if necessary.
        /// </param>
        /// <param name="written">
        /// The number of bytes written into the output span. This can be used to slice the output for 
        /// subsequent calls, if necessary.
        /// </param>
        /// <param name="isFinalBlock">
        /// <c>true</c> (default) when the input span contains the entire data to decode.
        /// Set to <c>false</c> only if it is known that the input span contains partial data with more data to follow.
        /// </param>
        /// <returns>
        /// It returns the OperationStatus enum values:
        /// <list type="bullet">
        /// <item><description>Done - on successful processing of the entire input span</description></item>
        /// <item><description>DestinationTooSmall - if there is not enough space in the output span to fit the decoded input</description></item>
        /// <item><description>
        /// NeedMoreData - only if isFinalBlock is false and the input is not a multiple of 4, otherwise the partial input 
        /// would be considered as InvalidData
        /// </description></item>
        /// <item><description>
        /// InvalidData - if the input contains chars outside of the expected base64 range, or if it contains invalid/more 
        /// than two padding characters, or if the input is incomplete (i.e. not a multiple of 4) and isFinalBlock is true.
        /// </description></item>
        /// </list>
        /// </returns>
        OperationStatus Decode(
            ReadOnlySpan<char> encoded,
            Span<byte>         data,
            out                int consumed,
            out                int written,
            bool               isFinalBlock = true);
        //---------------------------------------------------------------------
        /// <summary>
        /// Base64 encoded <paramref name="data" /> to a <see cref="string" />.
        /// </summary>
        /// <param name="data">The data to be base64 encoded.</param>
        /// <returns>The base64 encoded <see cref="string" />.</returns>
        string Encode(ReadOnlySpan<byte> data);
        //---------------------------------------------------------------------
        /// <summary>
        /// Base64 decodes <paramref name="encoded" /> into a <see cref="byte" /> array.
        /// </summary>
        /// <param name="encoded">The base64 encoded data in string-form.</param>
        /// <returns>The base64 decoded data.</returns>
        byte[] Decode(ReadOnlySpan<char> encoded);
    }
}
