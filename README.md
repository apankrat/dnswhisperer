# DNS Whisperer
DNS proxy for filtering out unwanted domains.

**What it is**

* Run `dnswhisperer` on some box
* Use this box as your DNS server
* Add some domains that you don't like to `dnswhisperer.txt`
* And voilà - all these domains will now shows up as "not found" on your machine

This is primarily meant for blocking online tracking and ad services.
In particular, this works well for devices that can't run ad-blocking capable browsers themselves.

**How it works**

It listens for DNS requests on UDP 0.0.0.0:53, checks that they are queries and checks all names from the Question section against the blacklist. It remembers the result and forwards request to a real DNS server.

When it receives a response, if it was a query for a blacklisted domain it changes the response code to NXDOMAIN ("not found"). It then forwards response to the client.

See code for details.

**Example**

Here's a single page load of https://reddit.com on iPad, each line is a DNS request:

            www.reddit.com
            www.redditstatic.com
            b.thumbs.redditmedia.com
            a.thumbs.redditmedia.com
            reddit.com
    nope -- ssl-google-analytics.l.google.com
    nope -- www-google-analytics.l.google.com
            www.redditmedia.com
    nope -- events.redditmedia.com
            pixel.redditmedia.com
    nope -- s.zkcdn.net
    nope -- www-googletagmanager.l.google.com

Line marked with **nope** are the DNS requests that were blocked.

**Caveats**

This code is few hours worth of effort. It's stable and reasonably clean, but it could use *lots* of improvement.

* Maxium number of in-flight (pending) requests is hardcoded to **256**.
* Real DNS address is hardcoded to **208.67.222.222**, one of OpenDNS servers.
* It uses a single socket to talk to the real DNS server, so the absolute maximum of in-flight requests is **2^16**, because  the Request ID field in a DNS packet is 16 bit wide. To increase this cap the code will simply need to maintain 2+ sockets and then track which request was forwarded to the server through which socket.
* Blacklist matching is as dumb as it gets - a linear scan with no less linear substring search of each entry in the query name.
* There's no support for proper clean up of timed out queries.
* Can't be daemonized at the moment.
* Logs to stdout.
* Uses select() - mortifying, granted, but, hey, there are just two sockets!

**Bulding**

1. Procure Linux
2. Run `make`

**Running**

`sudo ./dnswhisperer`

Sudo's needed because of listening on UDP/53, which is a privileged port. Alternatively, use [setuid](https://en.wikipedia.org/wiki/Setuid).
