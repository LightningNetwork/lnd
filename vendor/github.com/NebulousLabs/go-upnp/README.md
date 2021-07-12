## upnp ##

package upnp provides a simple and opinionated interface to UPnP-enabled
routers, allowing users to forward ports and discover their external IP
address. Specific quirks:

- When attempting to discover UPnP-enabled routers on the network, only the
first such router is returned. If you have multiple routers, this may cause
some trouble.

- Forwarded ports are always symmetric, e.g. the router's port 9980 will be
mapped to the client's port 9980. This will be unacceptable for some purposes,
but symmetric mappings are the desired behavior 99% of the time, and they
simplify the API.

- TCP and UDP protocols are forwarded together.

- Ports are forwarded permanently. Some other implementations lease a port
mapping for a set duration, and then renew it periodically. This is nice,
because it means mappings won't stick around after they've served their
purpose. Unfortunately, some routers only support permanent mappings, so this
package has chosen to support the lowest common denominator. To un-forward a
port, you must use the Clear function (or do it manually).

Once you've discovered your router, you can retrieve its address by calling
its Location method. This address can be supplied to Load to connect to the
router directly, which is much faster than calling Discover.

See the [godoc](http://godoc.org/github.com/NebulousLabs/go-upnp) for full documentation.

## example ##

```go
import (
	"log"
	"github.com/NebulousLabs/go-upnp"
)

func main() {
    // connect to router
    d, err := upnp.Discover()
    if err != nil {
        log.Fatal(err)
    }

    // discover external IP
    ip, err := d.ExternalIP()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Your external IP is:", ip)

    // forward a port
    err = d.Forward(9001, "upnp test")
    if err != nil {
        log.Fatal(err)
    }

    // un-forward a port
    err = d.Clear(9001)
    if err != nil {
        log.Fatal(err)
    }

    // record router's location
    loc := d.Location()

    // connect to router directly
    d, err = upnp.Load(loc)
    if err != nil {
        log.Fatal(err)
    }
}
```

## motivation ##

Port forwarding and external IP discovery are two of the most common tasks required when creating a P2P network. This requires talking to your local router, usually via the UPnP protocol. There are a number of existing packages that provide this functionality, but I found all of them lacking in some respect. The most robust implementation I found was huin's [goupnp](http://github.com/huin/goupnp), but its interface was clunky and required more boilerplate than I felt was necessary. So this package is really just a wrapper around the goupnp library, specifically tailored to the use cases listed above.

This makes the name a bit of a misnomer, I know; UPnP is much broader than port forwarding. But `upnp` is much more search-friendly than `igdman` (Internet Gateway Device Manager). If you think of something better, I'd love to hear it.
