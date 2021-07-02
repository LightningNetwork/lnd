# How to write a simple `lnd` client in Javascript using `node.js`

## Setup and Installation

First, you'll need to initialize a simple nodejs project:
```
npm init (or npm init -f if you want to use the default values without prompt)
```

Then you need to install the Javascript grpc and proto loader library
dependencies:
```
npm install grpc @grpc/proto-loader --save
```

You also need to copy the `lnd` `lightning.proto` file in your project directory
(or at least somewhere reachable by your Javascript code).

The `lightning.proto` file is [located in the `lnrpc` directory of the `lnd`
sources](https://github.com/lightningnetwork/lnd/blob/master/lnrpc/lightning.proto).

### Imports and Client

Every time you work with Javascript gRPC, you will have to import `grpc`, load
`lightning.proto`, and create a connection to your client like so:

```js
const grpc = require('grpc');
const protoLoader = require('@grpc/proto-loader');
const fs = require("fs");

// Due to updated ECDSA generated tls.cert we need to let gprc know that
// we need to use that cipher suite otherwise there will be a handhsake
// error when we communicate with the lnd rpc server.
process.env.GRPC_SSL_CIPHER_SUITES = 'HIGH+ECDSA'

// We need to give the proto loader some extra options, otherwise the code won't
// fully work with lnd.
const loaderOptions = {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true
};
const packageDefinition = protoLoader.loadSync('lightning.proto', loaderOptions);

//  Lnd cert is at ~/.lnd/tls.cert on Linux and
//  ~/Library/Application Support/Lnd/tls.cert on Mac
let lndCert = fs.readFileSync("~/.lnd/tls.cert");
let credentials = grpc.credentials.createSsl(lndCert);
let lnrpcDescriptor = grpc.loadPackageDefinition(packageDefinition);
let lnrpc = lnrpcDescriptor.lnrpc;
let lightning = new lnrpc.Lightning('localhost:10009', credentials);
```

## Examples

Let's walk through some examples of Javascript gRPC clients. These examples
assume that you have at least two `lnd` nodes running, the RPC location of one
of which is at the default `localhost:10009`, with an open channel between the
two nodes.

### Simple RPC

```js
lightning.getInfo({}, function(err, response) {
  if (err) {
    console.log('Error: ' + err);
  }
  console.log('GetInfo:', response);
});
```

You should get something like this in your console:

```
GetInfo: { identity_pubkey: '03c892e3f3f077ea1e381c081abb36491a2502bc43ed37ffb82e264224f325ff27',
  alias: '',
  num_pending_channels: 0,
  num_active_channels: 1,
  num_inactive_channels: 0,
  num_peers: 1,
  block_height: 1006,
  block_hash: '198ba1dc43b4190e507fa5c7aea07a74ec0009a9ab308e1736dbdab5c767ff8e',
  synced_to_chain: false,
  testnet: false,
  chains: [ 'bitcoin' ] }
```

### Response-streaming RPC

```js
let call = lightning.subscribeInvoices({});
call.on('data', function(invoice) {
    console.log(invoice);
})
.on('end', function() {
  // The server has finished sending
})
.on('status', function(status) {
  // Process status
  console.log("Current status" + status);
});
```

Now, create an invoice for your node at `localhost:10009`and send a payment to
it from another node.
```bash
$ lncli addinvoice --amt=100
{
	"r_hash": <RHASH>,
	"pay_req": <PAYMENT_REQUEST>
}
$ lncli sendpayment --pay_req=<PAYMENT_REQUEST>
```
Your Javascript console should now display the details of the recently satisfied
invoice.

### Bidirectional-streaming RPC

This example has a few dependencies:
```shell
⛰  npm install --save async lodash bytebuffer
```

You can run the following in your shell or put it in a program and run it like
`node script.js`

```js
// Load some libraries specific to this example
const async = require('async');
const _ = require('lodash');
const ByteBuffer = require('bytebuffer');

let dest_pubkey = <RECEIVER_ID_PUBKEY>;
let dest_pubkey_bytes = ByteBuffer.fromHex(dest_pubkey);

// Set a listener on the bidirectional stream
let call = lightning.sendPayment();
call.on('data', function(payment) {
  console.log("Payment sent:");
  console.log(payment);
});
call.on('end', function() {
  // The server has finished
  console.log("END");
});

// You can send single payments like this
call.write({ dest: dest_pubkey_bytes, amt: 6969 });

// Or send a bunch of them like this
function paymentSender(destination, amount) {
  return function(callback) {
    console.log("Sending " + amount + " satoshis");
    console.log("To: " + destination);
    call.write({
      dest: destination,
      amt: amount
    });
    _.delay(callback, 2000);
  };
}
let payment_senders = [];
for (let i = 0; i < 10; i++) {
  payment_senders[i] = paymentSender(dest_pubkey_bytes, 100);
}
async.series(payment_senders, function() {
  call.end();
});

```
This example will send a payment of 100 satoshis every 2 seconds.


### Using Macaroons

To authenticate using macaroons you need to include the macaroon in the metadata
of each request.

The following snippet will add the macaroon to every request automatically:

```js
const fs = require('fs');
const grpc = require('grpc');
const protoLoader = require('@grpc/proto-loader');
const loaderOptions = {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true
};
const packageDefinition = protoLoader.loadSync('lightning.proto', loaderOptions);

process.env.GRPC_SSL_CIPHER_SUITES = 'HIGH+ECDSA'

// Lnd admin macaroon is at ~/.lnd/data/chain/bitcoin/simnet/admin.macaroon on Linux and
// ~/Library/Application Support/Lnd/data/chain/bitcoin/simnet/admin.macaroon on Mac
let m = fs.readFileSync('~/.lnd/data/chain/bitcoin/simnet/admin.macaroon');
let macaroon = m.toString('hex');

// build meta data credentials
let metadata = new grpc.Metadata()
metadata.add('macaroon', macaroon)
let macaroonCreds = grpc.credentials.createFromMetadataGenerator((_args, callback) => {
  callback(null, metadata);
});

// build ssl credentials using the cert the same as before
let lndCert = fs.readFileSync("~/.lnd/tls.cert");
let sslCreds = grpc.credentials.createSsl(lndCert);

// combine the cert credentials and the macaroon auth credentials
// such that every call is properly encrypted and authenticated
let credentials = grpc.credentials.combineChannelCredentials(sslCreds, macaroonCreds);

// Pass the crendentials when creating a channel
let lnrpcDescriptor = grpc.loadPackageDefinition(packageDefinition);
let lnrpc = lnrpcDescriptor.lnrpc;
let client = new lnrpc.Lightning('some.address:10009', credentials);

client.getInfo({}, (err, response) => {
  if (err) {
    console.log('Error: ' + err);
  }
  console.log('GetInfo:', response);
});
```

## Conclusion

With the above, you should have all the `lnd` related `gRPC` dependencies
installed locally in your project. In order to get up to speed with `protofbuf`
usage from Javascript, see [this official `protobuf` reference for
Javascript](https://developers.google.com/protocol-buffers/docs/reference/javascript-generated).
Additionally, [this official gRPC
resource](http://www.grpc.io/docs/tutorials/basic/node.html) provides more
details around how to drive `gRPC` from `node.js`.

## API documentation

There is an [online API documentation](https://api.lightning.community?javascript)
available that shows all currently existing RPC methods, including code snippets
on how to use them.
