# Envoyant

Here's a local IPv4 HTTP/1.1 reverse-proxy built with Ruby on top of raw TCP stack.  
No reliance on gems outside of corelib and stdlib that come bundled with Ruby.  
All it really does is relay supported traffic to your backends residing on different ports, pretending to be your direct connection by replacing configured hostnames in HTTP/1.1 headers with respective IP:port combinations as you would use to access it otherwise.  
That prevents the server bickering about `Host`/`Origin` mismatch and denying you normal access.  
This is a quality-of-life toy for local environment. See if it suits your backends.  
Developed and tested with Ruby 3.2.2 on Windows 10. Expected to work fine and perhaps even better with Ruby 3.3.3+ and Unix.

## Purpose

You have many servers running locally and are having to keep track of each of their faceless port numbers to access them over `127.0.0.1`/`localhost` routeback.  
The `hosts` file or a DNS server isn't useful as a local solution, as they do not operate in respect to ports.  
With this script running, you can just access them as configured distinct memorable hostnames like `my.web-server.local` instead of juggling port numbers in your Web browser and sundry.  
Destinations are configured by extending your operating system's `hosts` file with port comments.

## Features

Communicates in HTTP/1.1 with support for chunked encoding and more.  
No support for TLS/SSL tested or expected. That applies to HTTPS.  
No support for IPv6.  
Allows protocol upgrade to WebSocket and associated bidirectional communication.  
Can optionally enforce single-turn HTTP/1.1 connections by suppressing `Connection: keep-alive` in relayed requests and sending `Connection: close` header on client's behalf. Not sure what you'd need that for, but it could be more stable, if rather slower, this way and help sidestep some edge-cases perhaps. This will not affect WebSocket connections — they are excluded from this processing.
I expect it to be possible to use this with external addresses, but didn't care to test this out-of-scope unintended functionality.

## Usage

1. Edit your system `hosts` file with root/admin privileges to define your endpoints.
  Find it in one of the following locations, depending on the OS.
  
  Windows:
  
  ```
  C:\Windows\System32\drivers\etc\hosts
  ```
  
  Unix:
  
  ```
  /etc/hosts
  ```
  
  To define endpoints, add or edit lines in your `hosts` file in the following format:
  
  ```
  IPv4 hostname # Envoyant: port
  ```
  
  - `IPv4` must be four numbers within range `0..255` separated by three periods. In most cases, your local servers are reachable on `127.0.0.1`. IPv6 has a different format and is not supported by Envoyant.
  - `hostname` must be any combination of lower-case of Latin/English letters, numbers `0..9`, hyphens `-` and periods `.`. Length of up to 63 characters is modernly defined as safe and up to 255 may be supported.
  - `#` begins a comment that terminates by the end of the line. Comments are ignored by the OS. They are parsed by Envoyant and possibly other programs.
  - `Envoyant:` is the specific comment marker that lets Envoyant know this entry should be routed by the script and must be present in a comment for Envoyant to process. Parsing of letter casing used for this comment marker is lenient.
  - `port` must be a number within range `1..65535`. You must set it to the port on which the server you intend to reach with the hostname is configured to listen for connection.
  - Spaces ` ` are only allowed as delimiters between these values. Parsing of spacing used for this purpose is lenient.
  
  Examples:
  
  ```
  127.0.0.1   comfyui.local                      # Envoyant: 8188
  127.0.0.1   sillytavern                        # Envoyant: 8000
  127.0.0.1   searx.instance                     # Envoyant: 8888
  200.1.2.3   singleword                         # Envoyant: 2123
  10.11.1.22                    fed.gov.elon.god # Envoyant: 1337
  78.0.20.100 ayy.lmao.co.uk.su.fed.gov.elon.god # Envoyant: 1337
  ```

2. Run the proxy as root/admin:
  
  ```sh
  ruby Envoyant/main.rb
  ```
  
  Optionally launch with keep-alive suppressed:
  
  ```sh
  ruby Envoyant/main.rb --keep-dead
  ```

3. Then access it in your Web browser like this after starting Envoyant:
  
  ```
  http://comfyui.local
  ```
  
  This would become equivalent to accessing:
  
  ```
  http://127.0.0.1:8188
  ```
  
  No more having to remember port numbers.

 4. Send ASCII `ETX` control code with `[Ctrl]+[C]` to the terminal focused or send `SIGINT` to shut down the proxy.  

## Logging

Terminal log only prints messages at or above INFO-level with severity ANSI-colorized, but only present digests for bodies.  
A new log file is written to the `./logs/` subdirectory next to the script on each launch until shutdown.  
File logs include full binary message bodies and additional DEBUG-level reports. Binary content may or may not be readable as plain text depending on the traffic relayed. Be mindful of what you open it with and which encoding is being interpreted.
Might add flags to set logging severity levels or optionally disable logging altogether in the future.

### Example


#### Log header

```
[34492] Relayed request 55560-=>8000
```

- `[34492]` is thread ID. Usually corresponds with client port.
- `55560` is client port. It is always on the left.
- `8000` is backend port. It is always on the right.
- `-=>` denotes a request. `<=-` denotes a response. `<=>` denotes bidirectional communication or very general reports.

#### Body digest.

```
Body: 72423 bytes. Hash: d1f26e9b
```

- `72423` is body content size in bytes.
- `d1f26e9b` is Adler-32 hexadecimal hash of the body content.

## Security

This script does effectively act as an an intermediary with full access to all your local traffic to the defined backends.  
An effort was made to parse and process as little of your traffic as possible — not so much out of privacy concern, as nobody but you is expected to be involved in running the script — moreso to ease complexity of developing the script with general-case solutions and simple, fast routing.  
There's only about 300 lines of code in the script, as of writing this here note — you can check that it never sends any of your data anywhere but the defined destinations.  

Every bit of information relayed is logged locally. You can inspect the logs to ensure what went where. But be mindful of who gets to access these logs.  
A feature implementation is pending to limit persistent logging in the future.  

Envoyant notionally sits between your client and backend as emissary, acting on their behalves, dispatching each request to the desired destination based on the hostname you use and relaying responses back. Neither side knows which port the other one really is communicating through. This is a side-effect of the way Envoyant operates to smooth out transport wrinkles that would otherwise arise and is not intended as any sort of privacy, anonymity or security feature.  

## License

This work, including all contents of the repository, is dedicated to public domain under [The Unlicense](https://unlicense.org/).  
It belongs to you, the user, as it belongs to everyone else.
