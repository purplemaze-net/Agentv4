# PurpleMaze Agent (Pagent) V4
## Introduction
As I own [PurpleMaze](https://purplemaze.net), an Anti-DDoS solution with rotating proxies, it became clear to me that I needed to find a way of authorizing only the IPs currently in use on customers' servers to prevent them from being scanned. So I developed this Pagent with this in mind.    

## Why open source?
as the software will be installed on the customer's server, I want to be as transparent as possible about its use.  
I updated the code from the previous (V3) version to be static, when it was before generated for each customer. If someone wants to reuse the port, they'll have to ensure the security of the web API endpoint (MasterUrl in src/FirewallManager.cs).

## How does it work?
On startup, the Pagent retrieves the list of IPs from the Master server and adds them to the whitelist of necessary ports, then closes these ports to the rest of the Internet.  
PurpleMaze's core servers make a request to the Pagent as soon as a proxy is created or deleted for the server, to add or remove its IP from the whitelist.  

## How to build ?
Well, even if I don't know why you would want to build it yourself, you can do it by:
- Clone the repo
- Replaceing the MasterUrl in src/FirewallManager.cs (and developing a compatible API endpoint, as specified in src/ApiStructures.cs)
- Install DotNet SDK 6.0+
- Run the "build.bat" file (Both Windows and Linux are supported)
- Solutions in `bin/Release/net6.0/linux-x64/publish` and `bin/Release/net6.0/win-x64/publish`


## Can I help ?
Of course! Don't hesitate to make a PR or contact me on Discord (@m2p_) if you see a possible improvement.  

### Post-Scriptum
Even if this software was designed to be open-source, I'm still a rookie, so some things may appears to be sloppy. I would be happy to know any improvment you'll make, just open an Issue/PR.