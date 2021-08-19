namespace NOnion.Http

open System
open System.Text
open System.IO
open System.IO.Compression

open NOnion
open NOnion.Network

type TorHttpClient (stream: TorStream, host: string) =

    // Receives all the data stream until it reaches EOF (until stream receive a RELAY_END)
    let rec receiveAll (state: array<byte>) =
        async {
            let! maybeNextPartialResponse = stream.Receive ()

            match maybeNextPartialResponse with
            | None -> return state
            | Some nextPartialResponse ->

                return!
                    Array.concat [ state
                                   nextPartialResponse ]
                    |> receiveAll
        }

    member __.GetAsString (path: string) (forceUncompressed: bool) =
        async {
            let headers =
                let supportedCompressionAlgorithms =
                    if forceUncompressed then
                        List.singleton "identity"
                    else
                        [ "deflate"; "identity" ]
                    |> String.concat ", "

                [
                    "Host", host
                    "Accept-Encoding", supportedCompressionAlgorithms
                ]
                |> List.map (fun (k, v) -> sprintf "%s: %s" k v)
                |> String.concat "\r\n"

            do!
                sprintf "GET %s HTTP/1.0\r\n%s\r\n\r\n" path headers
                |> Encoding.UTF8.GetBytes
                |> stream.SendData

            let! httpResponse = receiveAll Array.empty

            let header, body =
                let delimiter =
                    ReadOnlySpan (Encoding.ASCII.GetBytes "\r\n\r\n")

                let headerEndIndex =
                    MemoryExtensions.IndexOf (httpResponse.AsSpan (), delimiter)

                Encoding.UTF8.GetString (httpResponse, 0, headerEndIndex),
                httpResponse.[headerEndIndex + delimiter.Length..]

            let headerLines =
                header.Split (Array.singleton "\r\n", StringSplitOptions.None)

            let _protocol, status =
                let responseLine = headerLines.[0].Split ' '
                responseLine.[0], responseLine.[1]

            if status <> "200" then
                return
                    failwith (
                        sprintf "Non-200 status code received, code: %s" status
                    )

            let parseHeaderLine (header: string) =
                let splittedHeader =
                    header.Split (Array.singleton ": ", StringSplitOptions.None)

                splittedHeader.[0], splittedHeader.[1]

            let headersMap =
                headerLines
                |> Array.skip 1
                |> Array.map parseHeaderLine
                |> Map.ofArray

            match headersMap.TryGetValue "Content-Encoding" with
            | false, _ -> return failwith "Content-Encoding header is missing"
            | true, "identity" -> return body |> Encoding.UTF8.GetString
            | true, "deflate" ->
                // DeflateStream needs the zlib header to be chopped off first
                let body = Array.skip Constants.DeflateStreamHeaderLength body
                use outMemStream = new MemoryStream ()
                use inMemStream = new MemoryStream (body)

                use compressedStream =
                    new DeflateStream (
                        inMemStream,
                        CompressionMode.Decompress,
                        false
                    )

                do! compressedStream.CopyToAsync outMemStream |> Async.AwaitTask

                return outMemStream.ToArray () |> Encoding.UTF8.GetString
            | true, compressionMethod ->
                return
                    failwith (
                        sprintf
                            "Unknown content-encoding value, %s"
                            compressionMethod
                    )
        }

    member self.GetAsStringAsync path forceUncompressed =
        self.GetAsString path forceUncompressed |> Async.StartAsTask
