# How to write a C# gRPC client for the Lightning Network Daemon

This section enumerates what you need to do to write a client that communicates with `lnd` in C#.


### Prerequisites

* .Net Core [SDK](https://dotnet.microsoft.com/download)
* If using Windows, a unix terminal such as [Cygwin](https://www.cygwin.com/)


### Setup and Installation

`lnd` uses the `gRPC` protocol for communication with clients like `lncli`.

.NET natively supports gRPC proto files and generates the necessary C# classes. You can see the official Microsoft gRPC documentation [here](https://docs.microsoft.com/en-gb/aspnet/core/grpc/?view=aspnetcore-3.1)

This assumes you are using a Windows machine, but it applies equally to Mac and Linux.

Create a new `.net core` console application called `lndclient` at your root directory (On Windows : `C:/`).

Create a folder `Grpc` in the root of your project and fetch the lnd proto files

```shell
⛰  mkdir Grpc
⛰  curl -o Grpc/lightning.proto -s https://raw.githubusercontent.com/lightningnetwork/lnd/master/lnrpc/lightning.proto
```

Install `Grpc.Tools`, `Google.Protobuf`, `Grpc.Core` using NuGet or manually with `dotnet add`:

```shell
⛰  dotnet add package Grpc.Tools
⛰  dotnet add package Google.Protobuf
⛰  dotnet add package Grpc.Core
```

Add the `lightning.proto` file to the `.csproj` file in an ItemGroup. (In Visual Studio you can do this by unloading the project, editing the `.csproj` file and then reloading it)

```xml
<ItemGroup>
   <Protobuf Include="Grpc\lightning.proto" GrpcServices="Client" />
</ItemGroup>
```

You're done! Build the project and verify that it works.

#### Imports and Client

Use the code below to set up a channel and client to connect to your `lnd` node:

```cs
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Grpc.Core;
using Lnrpc;
...

// Due to updated ECDSA generated tls.cert we need to let gprc know that
// we need to use that cipher suite otherwise there will be a handshake
// error when we communicate with the lnd rpc server.
System.Environment.SetEnvironmentVariable("GRPC_SSL_CIPHER_SUITES", "HIGH+ECDSA");
            
// Lnd cert is at AppData/Local/Lnd/tls.cert on Windows
// ~/.lnd/tls.cert on Linux and ~/Library/Application Support/Lnd/tls.cert on Mac
var cert = File.ReadAllText(<Tls_Cert_Location>);

var sslCreds = new SslCredentials(cert);
var channel = new Grpc.Core.Channel("localhost:10009", sslCreds);
var client = new Lnrpc.Lightning.LightningClient(channel);
```

### Examples

Let's walk through some examples of C# `gRPC` clients. These examples assume that you have at least two `lnd` nodes running, the RPC location of one of which is at the default `localhost:10009`, with an open channel between the two nodes.

#### Simple RPC

```cs
// Retrieve and display the wallet balance
// Use "WalletBalanceAsync" if in async context
var response = client.WalletBalance(new WalletBalanceRequest());
Console.WriteLine(response);
```

#### Response-streaming RPC

```cs
var request = new InvoiceSubscription();
using (var call = client.SubscribeInvoices(request))
{
    while (await call.ResponseStream.MoveNext())
    {
        var invoice = call.ResponseStream.Current;
        Console.WriteLine(invoice.ToString());
    }
}
```

Now, create an invoice for your node at `localhost:10009` and send a payment to it from another node.
```shell
⛰  lncli addinvoice --amt=100
{
    "r_hash": <R_HASH>,
    "pay_req": <PAY_REQ>
}
⛰  lncli sendpayment --pay_req=<PAY_REQ>
```

Your console should now display the details of the recently satisfied invoice.

#### Bidirectional-streaming RPC

```cs
using (var call = client.SendPayment())
{
    var responseReaderTask = Task.Run(async () =>
    {
        while (await call.ResponseStream.MoveNext())
        {
            var payment = call.ResponseStream.Current;
            Console.WriteLine(payment.ToString());
        }
    });

    foreach (SendRequest sendRequest in SendPayment())
    {
        await call.RequestStream.WriteAsync(sendRequest);
    }
    await call.RequestStream.CompleteAsync();
    await responseReaderTask;
}


IEnumerable<SendRequest> SendPayment()
{
    while (true)
    {
        SendRequest req = new SendRequest() {
            DestString = <DEST_PUB_KEY>,
            Amt = 100,
            PaymentHashString = <R_HASH>,
            FinalCltvDelta = 144
        };
        yield return req;
        System.Threading.Thread.Sleep(2000);
    }
}
```
This example will send a payment of 100 satoshis every 2 seconds.

#### Using Macaroons

To authenticate using macaroons you need to include the macaroon in the metadata of the request.

```cs
// Lnd admin macaroon is at <LND_DIR>/data/chain/bitcoin/simnet/admin.macaroon on Windows
// ~/.lnd/data/chain/bitcoin/simnet/admin.macaroon on Linux and ~/Library/Application Support/Lnd/data/chain/bitcoin/simnet/admin.macaroon on Mac
byte[] macaroonBytes = File.ReadAllBytes("<LND_DIR>/data/chain/bitcoin/simnet/admin.macaroon");
var macaroon = BitConverter.ToString(macaroonBytes).Replace("-", ""); // hex format stripped of "-" chars
```

The simplest approach to use the macaroon is to include the metadata in each request as shown below.

```cs
client.GetInfo(new GetInfoRequest(), new Metadata() { new Metadata.Entry("macaroon", macaroon) });
```

However, this can get tiresome to do for each request, so to avoid explicitly including the macaroon we can update the credentials to include it automatically.

```cs
// build ssl credentials using the cert the same as before
var sslCreds = new SslCredentials(cert);

// combine the cert credentials and the macaroon auth credentials using interceptors
// so every call is properly encrypted and authenticated
Task AddMacaroon(AuthInterceptorContext context, Metadata metadata)
{
    metadata.Add(new Metadata.Entry("macaroon", macaroon));
    return Task.CompletedTask;
}
var macaroonInterceptor = new AsyncAuthInterceptor(AddMacaroon);
var combinedCreds = ChannelCredentials.Create(sslCreds, CallCredentials.FromInterceptor(macaroonInterceptor));

// finally pass in the combined credentials when creating a channel
var channel = new Grpc.Core.Channel("localhost:10009", combinedCreds);
var client = new Lnrpc.Lightning.LightningClient(channel);

// now every call will be made with the macaroon already included
client.GetInfo(new GetInfoRequest());
```


### Conclusion

With the above, you should have all the `lnd` related `gRPC` dependencies installed locally in your project. In order to get up to speed with `protobuf` usage from C#, see [this official `protobuf` tutorial for C#](https://developers.google.com/protocol-buffers/docs/csharptutorial). Additionally, [this official gRPC resource](http://www.grpc.io/docs/tutorials/basic/csharp.html) provides more details around how to drive `gRPC` from C#.