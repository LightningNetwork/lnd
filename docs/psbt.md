# PSBT

This document describes various use cases around the topic of Partially Signed
Bitcoin Transactions (PSBTs). `lnd`'s wallet now features a full set of PSBT
functionality, including creating, signing and funding channels with PSBTs.

See [BIP174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki) for
a full description of the PSBT format and the different _roles_ that a
participant in a PSBT can have.

To avoid possible malleability, all inputs to a funding transaction must be segwit
spends, meaning that P2PKH and normal P2SH cannot be used. An error will be
returned if any inputs are not segwit spends.

## Creating/funding a PSBT

The first step for every transaction that is constructed using a PSBT flow is to
select inputs (UTXOs) to fund the desired output and to add a change output that
sends the remaining funds back to the own wallet.

This `wallet psbt fund` command is very similar to `bitcoind`'s
`walletcreatefundedpsbt` command. One main difference is that you can specify a
template PSBT in the `lncli` variant that contains the output(s) and optional
inputs. Another difference is that for the `--outputs` flag, `lncli` expects the
amounts to be in satoshis instead of fractions of a bitcoin.

### Simple example: fund PSBT that sends to address

Let's start with a very simple example and assume we want to send half a coin
to the address `bcrt1qjrdns4f5zwkv29ln86plqzs092yd5fg6nsz8re`:

```shell
⛰  lncli wallet psbt fund --outputs='{"bcrt1qjrdns4f5zwkv29ln86plqzs092yd5fg6nsz8re":50000000}'
{
        "psbt": "cHNidP8BAHECAAAAAeJQY2VLRtutKgQYFUajEKpjFfl0Uyrm6x23OumDpe/4AQAAAAD/////AkxREgEAAAAAFgAUv6pTgbKHN60CZ+RQn5yOuH6c2WiA8PoCAAAAABYAFJDbOFU0E6zFF/M+g/AKDyqI2iUaAAAAAAABAOsCAAAAAAEBbxqXgEf9DlzcqqNM610s5pL1X258ra6+KJ22etb7HAcBAAAAAAAAAAACACT0AAAAAAAiACC7U1W0iJGhQ6o7CexDh5k36V6v3256xpA9/xmB2BybTFZdDQQAAAAAFgAUKp2ThzhswyM2QHlyvmMB6tQB7V0CSDBFAiEA4Md8RIZYqFdUPsgDyomlzMJL9bJ6Ho23JGTihXtEelgCIAeNXRLyt88SOuuWFVn3IodCE4U5D6DojIHesRmikF28ASEDHYFzMEAxfmfq98eSSnZtUwb1w7mAtHG65y8qiRFNnIkAAAAAAQEfVl0NBAAAAAAWABQqnZOHOGzDIzZAeXK+YwHq1AHtXQEDBAEAAAAAAAA=",
        "change_output_index": 0,
        "locks": [
                {
                        "id": "ede19a92ed321a4705f8a1cccc1d4f6182545d4bb4fae08bd5937831b7e38f98",
                        "outpoint": "f8efa583e93ab71debe62a5374f91563aa10a3461518042aaddb464b656350e2:1",
                        "expiration": 1601553408
                }
        ]
}
```

The first thing we notice in the response is that an outpoint was locked.
That means, the UTXO that was chosen to fund the PSBT is currently locked and
cannot be used by the internal wallet or any other RPC call. This lock will be
released automatically either after 10 minutes (timeout) or once a transaction
that spends the UTXO is published.

If we inspect the PSBT that was created, we see that the locked input was indeed
selected, the UTXO information was attached and a change output (at index 0) was
created as well:

```shell
⛰  bitcoin-cli decodepsbt cHNidP8BAHECAAAAAeJQY2VLRtutKgQYFUajEKpjFfl0Uyrm6x23OumDpe/4AQAAAAD/////AkxREgEAAAAAFgAUv6pTgbKHN60CZ+RQn5yOuH6c2WiA8PoCAAAAABYAFJDbOFU0E6zFF/M+g/AKDyqI2iUaAAAAAAABAOsCAAAAAAEBbxqXgEf9DlzcqqNM610s5pL1X258ra6+KJ22etb7HAcBAAAAAAAAAAACACT0AAAAAAAiACC7U1W0iJGhQ6o7CexDh5k36V6v3256xpA9/xmB2BybTFZdDQQAAAAAFgAUKp2ThzhswyM2QHlyvmMB6tQB7V0CSDBFAiEA4Md8RIZYqFdUPsgDyomlzMJL9bJ6Ho23JGTihXtEelgCIAeNXRLyt88SOuuWFVn3IodCE4U5D6DojIHesRmikF28ASEDHYFzMEAxfmfq98eSSnZtUwb1w7mAtHG65y8qiRFNnIkAAAAAAQEfVl0NBAAAAAAWABQqnZOHOGzDIzZAeXK+YwHq1AHtXQEDBAEAAAAAAAA=
{
  "tx": {
    "txid": "33a316d62ddf74656967754d26ea83a3cb89e03ae44578d965156d4b71b1fce7",
    "hash": "33a316d62ddf74656967754d26ea83a3cb89e03ae44578d965156d4b71b1fce7",
    "version": 2,
    "size": 113,
    "vsize": 113,
    "weight": 452,
    "locktime": 0,
    "vin": [
      {
        "txid": "f8efa583e93ab71debe62a5374f91563aa10a3461518042aaddb464b656350e2",
        "vout": 1,
        "scriptSig": {
          "asm": "",
          "hex": ""
        },
        "sequence": 4294967295
      }
    ],
    "vout": [
      {
        "value": 0.17977676,
        "n": 0,
        "scriptPubKey": {
          "asm": "0 bfaa5381b28737ad0267e4509f9c8eb87e9cd968",
          "hex": "0014bfaa5381b28737ad0267e4509f9c8eb87e9cd968",
          "reqSigs": 1,
          "type": "witness_v0_keyhash",
          "addresses": [
            "bcrt1qh7498qdjsum66qn8u3gfl8ywhplfektg6mutfs"
          ]
        }
      },
      {
        "value": 0.50000000,
        "n": 1,
        "scriptPubKey": {
          "asm": "0 90db38553413acc517f33e83f00a0f2a88da251a",
          "hex": "001490db38553413acc517f33e83f00a0f2a88da251a",
          "reqSigs": 1,
          "type": "witness_v0_keyhash",
          "addresses": [
            "bcrt1qjrdns4f5zwkv29ln86plqzs092yd5fg6nsz8re"
          ]
        }
      }
    ]
  },
  "unknown": {
  },
  "inputs": [
    {
      "witness_utxo": {
...
      },
      "non_witness_utxo": {
        ...
      },
      "sighash": "ALL"
    }
  ],
  "outputs": [
...
  ],
  "fee": 0.00007050
}
```

### Advanced example: fund PSBT with manual coin selection

Let's now look at how we can implement manual coin selection by using the `fund`
command. We again want to send half a coin to
`bcrt1qjrdns4f5zwkv29ln86plqzs092yd5fg6nsz8re` but we want to select our inputs
manually.

The first step is to look at all available UTXOs and choose. To do so, we use
the `listunspent` command:

```shell
⛰  lncli listunspent
{
        "utxos": [
                {
                        "address_type": 0,
                        "address": "bcrt1qmsq36rtc6ap3m0m6jryu0ez923et6kxrv46t4w",
                        "amount_sat": 100000000,
                        "pk_script": "0014dc011d0d78d7431dbf7a90c9c7e4455472bd58c3",
                        "outpoint": "3597b451ff56bc901eb806e8c644a004e934b4c208679756b4cddc455c768c48:1",
                        "confirmations": 6
                },
                {
                        "address_type": 0,
                        "address": "bcrt1q92we8pecdnpjxdjq09etuccpat2qrm2acu4256",
                        "amount_sat": 67984726,
                        "pk_script": "00142a9d9387386cc32336407972be6301ead401ed5d",
                        "outpoint": "f8efa583e93ab71debe62a5374f91563aa10a3461518042aaddb464b656350e2:1",
                        "confirmations": 24
                },
...
        ]
}
```

Next, we choose these two inputs and create the PSBT:

```shell
⛰  lncli wallet psbt fund --outputs='{"bcrt1qjrdns4f5zwkv29ln86plqzs092yd5fg6nsz8re":50000000}' \
    --inputs='["3597b451ff56bc901eb806e8c644a004e934b4c208679756b4cddc455c768c48:1","f8efa583e93ab71debe62a5374f91563aa10a3461518042aaddb464b656350e2:1"]'
{
        "psbt": "cHNidP8BAJoCAAAAAkiMdlxF3M20VpdnCMK0NOkEoETG6Aa4HpC8Vv9RtJc1AQAAAAAAAAAA4lBjZUtG260qBBgVRqMQqmMV+XRTKubrHbc66YOl7/gBAAAAAAAAAAACgPD6AgAAAAAWABSQ2zhVNBOsxRfzPoPwCg8qiNolGtIkCAcAAAAAFgAUuvRP5r7qAvj0egDxyX9/FH+vukgAAAAAAAEA3gIAAAAAAQEr9IZcho/gV/6fH8C8P+yhNRZP+l3YuxsyatdYcS0S6AEAAAAA/v///wLI/8+yAAAAABYAFDXoRFwgXNO5VVtVq2WpaENh6blAAOH1BQAAAAAWABTcAR0NeNdDHb96kMnH5EVUcr1YwwJHMEQCIDqugtYLp4ebJAZvOdieshLi1lLuPl2tHQG4jM4ybwEGAiBeMpCkbHBmzYvljxb1JBQyVAMuoco0xIfi+5OQdHuXaAEhAnH96NhTW09X0npE983YBsHUoMPI4U4xBtHenpZVTEqpVwAAAAEBHwDh9QUAAAAAFgAU3AEdDXjXQx2/epDJx+RFVHK9WMMBAwQBAAAAAAEA6wIAAAAAAQFvGpeAR/0OXNyqo0zrXSzmkvVfbnytrr4onbZ61vscBwEAAAAAAAAAAAIAJPQAAAAAACIAILtTVbSIkaFDqjsJ7EOHmTfpXq/fbnrGkD3/GYHYHJtMVl0NBAAAAAAWABQqnZOHOGzDIzZAeXK+YwHq1AHtXQJIMEUCIQDgx3xEhlioV1Q+yAPKiaXMwkv1snoejbckZOKFe0R6WAIgB41dEvK3zxI665YVWfcih0IThTkPoOiMgd6xGaKQXbwBIQMdgXMwQDF+Z+r3x5JKdm1TBvXDuYC0cbrnLyqJEU2ciQAAAAABAR9WXQ0EAAAAABYAFCqdk4c4bMMjNkB5cr5jAerUAe1dAQMEAQAAAAAAAA==",
        "change_output_index": 1,
        "locks": [
                {
                        "id": "ede19a92ed321a4705f8a1cccc1d4f6182545d4bb4fae08bd5937831b7e38f98",
                        "outpoint": "3597b451ff56bc901eb806e8c644a004e934b4c208679756b4cddc455c768c48:1",
                        "expiration": 1601560626
                },
                {
                        "id": "ede19a92ed321a4705f8a1cccc1d4f6182545d4bb4fae08bd5937831b7e38f98",
                        "outpoint": "f8efa583e93ab71debe62a5374f91563aa10a3461518042aaddb464b656350e2:1",
                        "expiration": 1601560626
                }
        ]
}
```

Inspecting this PSBT, we notice that the two inputs were chosen and a large
change change output was added at index 1:

```shell
⛰  bitcoin-cli  decodepsbt cHNidP8BAJoCAAAAAkiMdlxF3M20VpdnCMK0NOkEoETG6Aa4HpC8Vv9RtJc1AQAAAAAAAAAA4lBjZUtG260qBBgVRqMQqmMV+XRTKubrHbc66YOl7/gBAAAAAAAAAAACgPD6AgAAAAAWABSQ2zhVNBOsxRfzPoPwCg8qiNolGtIkCAcAAAAAFgAUuvRP5r7qAvj0egDxyX9/FH+vukgAAAAAAAEA3gIAAAAAAQEr9IZcho/gV/6fH8C8P+yhNRZP+l3YuxsyatdYcS0S6AEAAAAA/v///wLI/8+yAAAAABYAFDXoRFwgXNO5VVtVq2WpaENh6blAAOH1BQAAAAAWABTcAR0NeNdDHb96kMnH5EVUcr1YwwJHMEQCIDqugtYLp4ebJAZvOdieshLi1lLuPl2tHQG4jM4ybwEGAiBeMpCkbHBmzYvljxb1JBQyVAMuoco0xIfi+5OQdHuXaAEhAnH96NhTW09X0npE983YBsHUoMPI4U4xBtHenpZVTEqpVwAAAAEBHwDh9QUAAAAAFgAU3AEdDXjXQx2/epDJx+RFVHK9WMMBAwQBAAAAAAEA6wIAAAAAAQFvGpeAR/0OXNyqo0zrXSzmkvVfbnytrr4onbZ61vscBwEAAAAAAAAAAAIAJPQAAAAAACIAILtTVbSIkaFDqjsJ7EOHmTfpXq/fbnrGkD3/GYHYHJtMVl0NBAAAAAAWABQqnZOHOGzDIzZAeXK+YwHq1AHtXQJIMEUCIQDgx3xEhlioV1Q+yAPKiaXMwkv1snoejbckZOKFe0R6WAIgB41dEvK3zxI665YVWfcih0IThTkPoOiMgd6xGaKQXbwBIQMdgXMwQDF+Z+r3x5JKdm1TBvXDuYC0cbrnLyqJEU2ciQAAAAABAR9WXQ0EAAAAABYAFCqdk4c4bMMjNkB5cr5jAerUAe1dAQMEAQAAAAAAAA==
{
"tx": {
  "txid": "e62356b99c3097eaa1241ff8e39b996917e66b13e4c0ccba3698982d746c3b76",
  "hash": "e62356b99c3097eaa1241ff8e39b996917e66b13e4c0ccba3698982d746c3b76",
  "version": 2,
  "size": 154,
  "vsize": 154,
  "weight": 616,
  "locktime": 0,
  "vin": [
    {
      "txid": "3597b451ff56bc901eb806e8c644a004e934b4c208679756b4cddc455c768c48",
      "vout": 1,
      "scriptSig": {
        "asm": "",
        "hex": ""
      },
      "sequence": 0
    },
    {
      "txid": "f8efa583e93ab71debe62a5374f91563aa10a3461518042aaddb464b656350e2",
      "vout": 1,
      "scriptSig": {
        "asm": "",
        "hex": ""
      },
      "sequence": 0
    }
  ],
  "vout": [
    {
      "value": 0.50000000,
      "n": 0,
      "scriptPubKey": {
        "asm": "0 90db38553413acc517f33e83f00a0f2a88da251a",
        "hex": "001490db38553413acc517f33e83f00a0f2a88da251a",
        "reqSigs": 1,
        "type": "witness_v0_keyhash",
        "addresses": [
          "bcrt1qjrdns4f5zwkv29ln86plqzs092yd5fg6nsz8re"
        ]
      }
    },
    {
      "value": 1.17974226,
      "n": 1,
      "scriptPubKey": {
        "asm": "0 baf44fe6beea02f8f47a00f1c97f7f147fafba48",
        "hex": "0014baf44fe6beea02f8f47a00f1c97f7f147fafba48",
        "reqSigs": 1,
        "type": "witness_v0_keyhash",
        "addresses": [
          "bcrt1qht6yle47agp03ar6qrcujlmlz3l6lwjgjv36zl"
        ]
      }
    }
  ]
},
"unknown": {
},
"inputs": [
...
],
"outputs": [
...
],
"fee": 0.00010500
}
```

## Signing and finalizing a PSBT

Assuming we now want to sign the transaction that we created in the previous
example, we simply pass it to the `finalize` sub command of the wallet:

```shell
⛰  lncli wallet psbt finalize cHNidP8BAJoCAAAAAkiMdlxF3M20VpdnCMK0NOkEoETG6Aa4HpC8Vv9RtJc1AQAAAAAAAAAA4lBjZUtG260qBBgVRqMQqmMV+XRTKubrHbc66YOl7/gBAAAAAAAAAAACgPD6AgAAAAAWABSQ2zhVNBOsxRfzPoPwCg8qiNolGtIkCAcAAAAAFgAUuvRP5r7qAvj0egDxyX9/FH+vukgAAAAAAAEA3gIAAAAAAQEr9IZcho/gV/6fH8C8P+yhNRZP+l3YuxsyatdYcS0S6AEAAAAA/v///wLI/8+yAAAAABYAFDXoRFwgXNO5VVtVq2WpaENh6blAAOH1BQAAAAAWABTcAR0NeNdDHb96kMnH5EVUcr1YwwJHMEQCIDqugtYLp4ebJAZvOdieshLi1lLuPl2tHQG4jM4ybwEGAiBeMpCkbHBmzYvljxb1JBQyVAMuoco0xIfi+5OQdHuXaAEhAnH96NhTW09X0npE983YBsHUoMPI4U4xBtHenpZVTEqpVwAAAAEBHwDh9QUAAAAAFgAU3AEdDXjXQx2/epDJx+RFVHK9WMMBAwQBAAAAAAEA6wIAAAAAAQFvGpeAR/0OXNyqo0zrXSzmkvVfbnytrr4onbZ61vscBwEAAAAAAAAAAAIAJPQAAAAAACIAILtTVbSIkaFDqjsJ7EOHmTfpXq/fbnrGkD3/GYHYHJtMVl0NBAAAAAAWABQqnZOHOGzDIzZAeXK+YwHq1AHtXQJIMEUCIQDgx3xEhlioV1Q+yAPKiaXMwkv1snoejbckZOKFe0R6WAIgB41dEvK3zxI665YVWfcih0IThTkPoOiMgd6xGaKQXbwBIQMdgXMwQDF+Z+r3x5JKdm1TBvXDuYC0cbrnLyqJEU2ciQAAAAABAR9WXQ0EAAAAABYAFCqdk4c4bMMjNkB5cr5jAerUAe1dAQMEAQAAAAAAAA==
{
      "psbt": "cHNidP8BAJoCAAAAAkiMdlxF3M20VpdnCMK0NOkEoETG6Aa4HpC8Vv9RtJc1AQAAAAAAAAAA4lBjZUtG260qBBgVRqMQqmMV+XRTKubrHbc66YOl7/gBAAAAAAAAAAACgPD6AgAAAAAWABSQ2zhVNBOsxRfzPoPwCg8qiNolGtIkCAcAAAAAFgAUuvRP5r7qAvj0egDxyX9/FH+vukgAAAAAAAEA3gIAAAAAAQEr9IZcho/gV/6fH8C8P+yhNRZP+l3YuxsyatdYcS0S6AEAAAAA/v///wLI/8+yAAAAABYAFDXoRFwgXNO5VVtVq2WpaENh6blAAOH1BQAAAAAWABTcAR0NeNdDHb96kMnH5EVUcr1YwwJHMEQCIDqugtYLp4ebJAZvOdieshLi1lLuPl2tHQG4jM4ybwEGAiBeMpCkbHBmzYvljxb1JBQyVAMuoco0xIfi+5OQdHuXaAEhAnH96NhTW09X0npE983YBsHUoMPI4U4xBtHenpZVTEqpVwAAAAEBHwDh9QUAAAAAFgAU3AEdDXjXQx2/epDJx+RFVHK9WMMBCGwCSDBFAiEAuiv52IX5wZlYJqqVGsQPfeQ/kneCNRD34v5yplNpuMYCIECHVUhjHPKSiWSsYEKD4JWGAyUwQHgDytA1whFOyLclASECg7PDfGE/uURta5/R42Vso6QKmVAgYMhjWlXENkE/x+QAAQDrAgAAAAABAW8al4BH/Q5c3KqjTOtdLOaS9V9ufK2uviidtnrW+xwHAQAAAAAAAAAAAgAk9AAAAAAAIgAgu1NVtIiRoUOqOwnsQ4eZN+ler99uesaQPf8Zgdgcm0xWXQ0EAAAAABYAFCqdk4c4bMMjNkB5cr5jAerUAe1dAkgwRQIhAODHfESGWKhXVD7IA8qJpczCS/Wyeh6NtyRk4oV7RHpYAiAHjV0S8rfPEjrrlhVZ9yKHQhOFOQ+g6IyB3rEZopBdvAEhAx2BczBAMX5n6vfHkkp2bVMG9cO5gLRxuucvKokRTZyJAAAAAAEBH1ZdDQQAAAAAFgAUKp2ThzhswyM2QHlyvmMB6tQB7V0BCGwCSDBFAiEAqK7FSrqWe2non0kl96yu2+gSXGPYPC7ZjzVZEMMWtpYCIGTzCDHZhJYGPrsnBWU8o0Eyd4nBa+6d037xGFcGUYJLASECORgkj75Xu8+DTh8bqYBIvNx1hSxV7VSJOwY6jam6LY8AAAA=",
      "final_tx": "02000000000102488c765c45dccdb456976708c2b434e904a044c6e806b81e90bc56ff51b49735010000000000000000e25063654b46dbad2a04181546a310aa6315f974532ae6eb1db73ae983a5eff80100000000000000000280f0fa020000000016001490db38553413acc517f33e83f00a0f2a88da251ad224080700000000160014baf44fe6beea02f8f47a00f1c97f7f147fafba4802483045022100ba2bf9d885f9c1995826aa951ac40f7de43f9277823510f7e2fe72a65369b8c6022040875548631cf2928964ac604283e09586032530407803cad035c2114ec8b72501210283b3c37c613fb9446d6b9fd1e3656ca3a40a99502060c8635a55c436413fc7e402483045022100a8aec54aba967b69e89f4925f7acaedbe8125c63d83c2ed98f355910c316b696022064f30831d98496063ebb2705653ca341327789c16bee9dd37ef118570651824b0121023918248fbe57bbcf834e1f1ba98048bcdc75852c55ed54893b063a8da9ba2d8f00000000"
}
```

That final transaction can now, in theory, be broadcast. But **it is very
important** that you **do not** publish it manually if any of the involved
outputs are used to fund a channel. See
[the safety warning below](#safety-warning) to learn the reason for this.

## Opening a channel by using a PSBT

This is a step-by-step guide on how to open a channel with `lnd` by using a PSBT
as the funding transaction.  
We will use `bitcoind` to create and sign the transaction just to keep the
example simple. Of course any other PSBT compatible wallet could be used and the
process would likely be spread out over multiple signing steps. The goal of this
example is not to cover each and every possible edge case but to help users of
`lnd` understand what inputs the `lncli` utility expects.

The goal is to open a channel of 1'234'567 satoshis to the node
`03db1e56e5f76bc4018cf6f03d1bb98a7ae96e3f18535e929034f85e7f1ca2b8ac` by using
a PSBT. That means, `lnd` can have a wallet balance of `0` and is still able to
open a channel. We'll jump into an example right away.

The new funding flow has a small caveat: _Time matters_.
  
When opening a channel using the PSBT flow, we start the negotiation
with the remote peer immediately so we can obtain their multisig key they are
going to use for the channel. Then we pause the whole process until we get a
fully signed transaction back from the user. Unfortunately there is no reliable
way to know after how much time the remote node starts to clean up and "forgets"
about the pending channel. If the remote node is an `lnd` node, we know it's
after 10 minutes. **So as long as the whole process takes less than 10 minutes,
everything should work fine.**

### Safety warning

**DO NOT PUBLISH** the finished transaction by yourself or with another tool.
lnd MUST publish it in the proper funding flow order **OR THE FUNDS CAN BE
LOST**!

This is very important to remember when using wallets like `Wasabi` for
instance, where the "publish" button is very easy to hit by accident.

### 1. Use the new `--psbt` flag in `lncli openchannel`

The new `--psbt` flag in the `openchannel` command starts an interactive dialog
between `lncli` and the user. Below the command you see an example output from
a regtest setup. Of course all values will be different.

```shell
⛰  lncli openchannel --node_key 03db1e56e5f76bc4018cf6f03d1bb98a7ae96e3f18535e929034f85e7f1ca2b8ac --local_amt 1234567 --psbt
Starting PSBT funding flow with pending channel ID fc7853889a04d33b8115bd79ebc99c5eea80d894a0bead40fae5a06bcbdccd3d.
PSBT funding initiated with peer 03db1e56e5f76bc4018cf6f03d1bb98a7ae96e3f18535e929034f85e7f1ca2b8ac.
Please create a PSBT that sends 0.01234567 BTC (1234567 satoshi) to the funding address bcrt1qh33ghvgjj3ef625nl9jxz6nnrz2z9e65vsdey7w5msrklgr6rc0sv0s08q.

Example with bitcoind:
        bitcoin-cli walletcreatefundedpsbt [] '[{"bcrt1qh33ghvgjj3ef625nl9jxz6nnrz2z9e65vsdey7w5msrklgr6rc0sv0s08q":0.01234567}]'

Or if you are using a wallet that can fund a PSBT directly (currently not
possible with bitcoind), you can use this PSBT that contains the same address
and amount: cHNidP8BADUCAAAAAAGH1hIAAAAAACIAILxii7ESlHKdKpP5ZGFqcxiUIudUZBuSedTcB2+geh4fAAAAAAAA

Paste the funded PSBT here to continue the funding flow.
Base64 encoded PSBT:
```

The command line now waits until a PSBT is entered. We'll create one in the next
step. Make sure to use a new shell window/tab for the next commands and leave
the prompt from the `openchannel` running as is.

### 2a. Use `bitcoind` to create a funding transaction

The output of the last command already gave us an example command to use with
`bitcoind`. We'll go ahead and execute it now. The meaning of this command is
something like "bitcoind, give me a PSBT that sends the given amount to the
given address, choose any input you see fit":

```shell
⛰  bitcoin-cli walletcreatefundedpsbt [] '[{"bcrt1qh33ghvgjj3ef625nl9jxz6nnrz2z9e65vsdey7w5msrklgr6rc0sv0s08q":0.01234567}]'
{
  "psbt": "cHNidP8BAH0CAAAAAbxLLf9+AYfqfF69QAQuETnL6cas7GDiWBZF+3xxc/Y/AAAAAAD+////AofWEgAAAAAAIgAgvGKLsRKUcp0qk/lkYWpzGJQi51RkG5J51NwHb6B6Hh+1If0jAQAAABYAFL+6THEGhybJnOkFGSRFbtCcPOG8AAAAAAABAR8wBBAkAQAAABYAFHemJ11XF7CU7WXBIJLD/qZF+6jrAAAA",
  "fee": 0.00003060,
  "changepos": 1
}
```

We see that `bitcoind` has given us a transaction that would pay `3060` satoshi
in fees. Fee estimation/calculation can be changed with parameters of the 
`walletcreatefundedpsbt` command. To see all options, use
`bitcoin-cli help walletcreatefundedpsbt`.

If we want to know what exactly is in this PSBT, we can look at it with the
`decodepsbt` command:

```shell
⛰  bitcoin-cli decodepsbt cHNidP8BAH0CAAAAAbxLLf9+AYfqfF69QAQuETnL6cas7GDiWBZF+3xxc/Y/AAAAAAD+////AofWEgAAAAAAIgAgvGKLsRKUcp0qk/lkYWpzGJQi51RkG5J51NwHb6B6Hh+1If0jAQAAABYAFL+6THEGhybJnOkFGSRFbtCcPOG8AAAAAAABAR8wBBAkAQAAABYAFHemJ11XF7CU7WXBIJLD/qZF+6jrAAAA
{
  "tx": {
    "txid": "374504e4246a93a45b4a2c2bc31d8adc8525aa101c7b9065db6dc01c4bdfce0a",
    "hash": "374504e4246a93a45b4a2c2bc31d8adc8525aa101c7b9065db6dc01c4bdfce0a",
    "version": 2,
    "size": 125,
    "vsize": 125,
    "weight": 500,
    "locktime": 0,
    "vin": [
      {
        "txid": "3ff673717cfb451658e260ecacc6e9cb39112e0440bd5e7cea87017eff2d4bbc",
        "vout": 0,
        "scriptSig": {
          "asm": "",
          "hex": ""
        },
        "sequence": 4294967294
      }
    ],
    "vout": [
      {
        "value": 0.01234567,
        "n": 0,
        "scriptPubKey": {
          "asm": "0 bc628bb11294729d2a93f964616a73189422e754641b9279d4dc076fa07a1e1f",
          "hex": "0020bc628bb11294729d2a93f964616a73189422e754641b9279d4dc076fa07a1e1f",
          "reqSigs": 1,
          "type": "witness_v0_scripthash",
          "addresses": [
            "bcrt1qh33ghvgjj3ef625nl9jxz6nnrz2z9e65vsdey7w5msrklgr6rc0sv0s08q"
          ]
        }
      },
      {
        "value": 48.98759093,
        "n": 1,
        "scriptPubKey": {
          "asm": "0 bfba4c71068726c99ce9051924456ed09c3ce1bc",
          "hex": "0014bfba4c71068726c99ce9051924456ed09c3ce1bc",
          "reqSigs": 1,
          "type": "witness_v0_keyhash",
          "addresses": [
            "bcrt1qh7aycugxsunvn88fq5vjg3tw6zwrecduvvgre5"
          ]
        }
      }
    ]
  },
  "unknown": {
  },
  "inputs": [
    {
      "witness_utxo": {
        "amount": 48.99996720,
        "scriptPubKey": {
          "asm": "0 77a6275d5717b094ed65c12092c3fea645fba8eb",
          "hex": "001477a6275d5717b094ed65c12092c3fea645fba8eb",
          "type": "witness_v0_keyhash",
          "address": "bcrt1qw7nzwh2hz7cffmt9cysf9sl75ezlh28tzl4n4e"
        }
      }
    }
  ],
  "outputs": [
    {
    },
    {
    }
  ],
  "fee": 0.00003060
}
```

This tells us that we got a PSBT with a big input, the channel output and a
change output for the rest. Everything is there but the signatures/witness data,
which is exactly what we need.

### 2b. Use `lnd` to create a funding transaction

Starting with version `v0.12.0`, `lnd` can also create PSBTs. This assumes a
scenario where one instance of `lnd` only has public keys (watch only mode) and
a secondary, hardened and firewalled `lnd` instance has the corresponding
private keys. On the watching only mode, the following command can be used to
create the funding PSBT:

```shell
⛰  lncli wallet psbt fund --outputs='{"bcrt1qh33ghvgjj3ef625nl9jxz6nnrz2z9e65vsdey7w5msrklgr6rc0sv0s08q":1234567}'
{
        "psbt": "cHNidP8BAH0CAAAAAUiMdlxF3M20VpdnCMK0NOkEoETG6Aa4HpC8Vv9RtJc1AQAAAAD/////AofWEgAAAAAAIgAgvGKLsRKUcp0qk/lkYWpzGJQi51RkG5J51NwHb6B6Hh+X7OIFAAAAABYAFNigOB6EbCLRi+Evlv4r2yJx63NxAAAAAAABAN4CAAAAAAEBK/SGXIaP4Ff+nx/AvD/soTUWT/pd2LsbMmrXWHEtEugBAAAAAP7///8CyP/PsgAAAAAWABQ16ERcIFzTuVVbVatlqWhDYem5QADh9QUAAAAAFgAU3AEdDXjXQx2/epDJx+RFVHK9WMMCRzBEAiA6roLWC6eHmyQGbznYnrIS4tZS7j5drR0BuIzOMm8BBgIgXjKQpGxwZs2L5Y8W9SQUMlQDLqHKNMSH4vuTkHR7l2gBIQJx/ejYU1tPV9J6RPfN2AbB1KDDyOFOMQbR3p6WVUxKqVcAAAABAR8A4fUFAAAAABYAFNwBHQ1410Mdv3qQycfkRVRyvVjDAQMEAQAAAAAAAA==",
        "change_output_index": 1,
        "locks": [
                {
                        "id": "ede19a92ed321a4705f8a1cccc1d4f6182545d4bb4fae08bd5937831b7e38f98",
                        "outpoint": "3597b451ff56bc901eb806e8c644a004e934b4c208679756b4cddc455c768c48:1",
                        "expiration": 1601562037
                }
        ]
}
```

### 3. Verify and sign the PSBT

Now that we have a valid PSBT that has everything but the final
signatures/witness data, we can paste it into the prompt in `lncli` that is
still waiting for our input.

```shell
...
Base64 encoded PSBT: cHNidP8BAH0CAAAAAbxLLf9+AYfqfF69QAQuETnL6cas7GDiWBZF+3xxc/Y/AAAAAAD+////AofWEgAAAAAAIgAgvGKLsRKUcp0qk/lkYWpzGJQi51RkG5J51NwHb6B6Hh+1If0jAQAAABYAFL+6THEGhybJnOkFGSRFbtCcPOG8AAAAAAABAR8wBBAkAQAAABYAFHemJ11XF7CU7WXBIJLD/qZF+6jrAAAA

PSBT verified by lnd, please continue the funding flow by signing the PSBT by
all required parties/devices. Once the transaction is fully signed, paste it
again here.

Base64 encoded PSBT:
```

We can now go ahead and sign the transaction. We are going to use `bitcoind` for
this again, but in practice this would now happen on a hardware wallet and
perhaps `bitcoind` would only know the public keys and couldn't sign for the
transaction itself. Again, this is only an example and can't reflect all
real-world use cases.

```shell
⛰  bitcoin-cli walletprocesspsbt cHNidP8BAH0CAAAAAbxLLf9+AYfqfF69QAQuETnL6cas7GDiWBZF+3xxc/Y/AAAAAAD+////AofWEgAAAAAAIgAgvGKLsRKUcp0qk/lkYWpzGJQi51RkG5J51NwHb6B6Hh+1If0jAQAAABYAFL+6THEGhybJnOkFGSRFbtCcPOG8AAAAAAABAR8wBBAkAQAAABYAFHemJ11XF7CU7WXBIJLD/qZF+6jrAAAA
{
"psbt": "cHNidP8BAH0CAAAAAbxLLf9+AYfqfF69QAQuETnL6cas7GDiWBZF+3xxc/Y/AAAAAAD+////AofWEgAAAAAAIgAgvGKLsRKUcp0qk/lkYWpzGJQi51RkG5J51NwHb6B6Hh+1If0jAQAAABYAFL+6THEGhybJnOkFGSRFbtCcPOG8AAAAAAABAR8wBBAkAQAAABYAFHemJ11XF7CU7WXBIJLD/qZF+6jrAQhrAkcwRAIgHKQbenZYvgADRd9TKGVO36NnaIgW3S12OUg8XGtSrE8CICmeaYoJ/U7Ecm+/GneY8i2hu2QCaQnuomJgzn+JAnrDASEDUBmCLcsybA5qXSRBBdZ0Uk/FQiay9NgOpv4D26yeJpAAAAA=",
"complete": true
}
```

If you are using the two `lnd` node model as described in
[2b](#2b-use-lnd-to-create-a-funding-transaction), you can achieve the same
result with the following command:

```shell
⛰  lncli wallet psbt finalize cHNidP8BAH0CAAAAAUiMdlxF3M20VpdnCMK0NOkEoETG6Aa4HpC8Vv9RtJc1AQAAAAD/////AofWEgAAAAAAIgAgvGKLsRKUcp0qk/lkYWpzGJQi51RkG5J51NwHb6B6Hh+X7OIFAAAAABYAFNigOB6EbCLRi+Evlv4r2yJx63NxAAAAAAABAN4CAAAAAAEBK/SGXIaP4Ff+nx/AvD/soTUWT/pd2LsbMmrXWHEtEugBAAAAAP7///8CyP/PsgAAAAAWABQ16ERcIFzTuVVbVatlqWhDYem5QADh9QUAAAAAFgAU3AEdDXjXQx2/epDJx+RFVHK9WMMCRzBEAiA6roLWC6eHmyQGbznYnrIS4tZS7j5drR0BuIzOMm8BBgIgXjKQpGxwZs2L5Y8W9SQUMlQDLqHKNMSH4vuTkHR7l2gBIQJx/ejYU1tPV9J6RPfN2AbB1KDDyOFOMQbR3p6WVUxKqVcAAAABAR8A4fUFAAAAABYAFNwBHQ1410Mdv3qQycfkRVRyvVjDAQMEAQAAAAAAAA==
{
        "psbt": "cHNidP8BAH0CAAAAAUiMdlxF3M20VpdnCMK0NOkEoETG6Aa4HpC8Vv9RtJc1AQAAAAD/////AofWEgAAAAAAIgAgvGKLsRKUcp0qk/lkYWpzGJQi51RkG5J51NwHb6B6Hh+X7OIFAAAAABYAFNigOB6EbCLRi+Evlv4r2yJx63NxAAAAAAABAN4CAAAAAAEBK/SGXIaP4Ff+nx/AvD/soTUWT/pd2LsbMmrXWHEtEugBAAAAAP7///8CyP/PsgAAAAAWABQ16ERcIFzTuVVbVatlqWhDYem5QADh9QUAAAAAFgAU3AEdDXjXQx2/epDJx+RFVHK9WMMCRzBEAiA6roLWC6eHmyQGbznYnrIS4tZS7j5drR0BuIzOMm8BBgIgXjKQpGxwZs2L5Y8W9SQUMlQDLqHKNMSH4vuTkHR7l2gBIQJx/ejYU1tPV9J6RPfN2AbB1KDDyOFOMQbR3p6WVUxKqVcAAAABAR8A4fUFAAAAABYAFNwBHQ1410Mdv3qQycfkRVRyvVjDAQhrAkcwRAIgU3Ow7cLkKrg8BJe0U0n9qFLPizqEzY0JtjVlpWOEk14CID/4AFNfgwNENN2LoOs0C6uHgt4sk8rNoZG+VMGzOC/HASECg7PDfGE/uURta5/R42Vso6QKmVAgYMhjWlXENkE/x+QAAAA=",
        "final_tx": "02000000000101488c765c45dccdb456976708c2b434e904a044c6e806b81e90bc56ff51b497350100000000ffffffff0287d6120000000000220020bc628bb11294729d2a93f964616a73189422e754641b9279d4dc076fa07a1e1f97ece20500000000160014d8a0381e846c22d18be12f96fe2bdb2271eb73710247304402205373b0edc2e42ab83c0497b45349fda852cf8b3a84cd8d09b63565a56384935e02203ff800535f83034434dd8ba0eb340bab8782de2c93cacda191be54c1b3382fc701210283b3c37c613fb9446d6b9fd1e3656ca3a40a99502060c8635a55c436413fc7e400000000"
}
```

Interpreting the output, we now have a complete, final, and signed transaction
inside the PSBT.

**!!! WARNING !!!**

**DO NOT PUBLISH** the finished transaction by yourself or with another tool.
lnd MUST publish it in the proper funding flow order **OR THE FUNDS CAN BE
LOST**!

Let's give it to `lncli` to continue:

```shell
...
Base64 encoded PSBT: cHNidP8BAH0CAAAAAbxLLf9+AYfqfF69QAQuETnL6cas7GDiWBZF+3xxc/Y/AAAAAAD+////AofWEgAAAAAAIgAgvGKLsRKUcp0qk/lkYWpzGJQi51RkG5J51NwHb6B6Hh+1If0jAQAAABYAFL+6THEGhybJnOkFGSRFbtCcPOG8AAAAAAABAR8wBBAkAQAAABYAFHemJ11XF7CU7WXBIJLD/qZF+6jrAQhrAkcwRAIgHKQbenZYvgADRd9TKGVO36NnaIgW3S12OUg8XGtSrE8CICmeaYoJ/U7Ecm+/GneY8i2hu2QCaQnuomJgzn+JAnrDASEDUBmCLcsybA5qXSRBBdZ0Uk/FQiay9NgOpv4D26yeJpAAAAA=
{
        "funding_txid": "374504e4246a93a45b4a2c2bc31d8adc8525aa101c7b9065db6dc01c4bdfce0a"
}
```

Success! We now have the final transaction ID of the published funding
transaction. Now we only have to wait for some confirmations, then we can start
using the freshly created channel.

## Batch opening channels

The PSBT channel funding flow makes it possible to open multiple channels in one
transaction. This can be achieved by taking the initial PSBT returned by the
`openchannel` and feed it into the `--base_psbt` parameter of the next
`openchannel` command. This won't work with `bitcoind` though, as it cannot take
a PSBT as partial input for the `walletcreatefundedpsbt` command.

However, the `bitcoin-cli` examples from the command line can be combined into
a single command. For example:

Channel 1:
```shell
⛰  bitcoin-cli walletcreatefundedpsbt [] '[{"tb1qywvazres587w9wyy8uw03q8j9ek6gc9crwx4jvhqcmew4xzsvqcq3jjdja":0.01000000}]'
```

Channel 2:
```shell
⛰  bitcoin-cli walletcreatefundedpsbt [] '[{"tb1q53626fcwwtcdc942zaf4laqnr3vg5gv4g0hakd2h7fw2pmz6428sk3ezcx":0.01000000}]'
```

Combined command to get batch PSBT:
```shell
⛰  bitcoin-cli walletcreatefundedpsbt [] '[{"tb1q53626fcwwtcdc942zaf4laqnr3vg5gv4g0hakd2h7fw2pmz6428sk3ezcx":0.01000000},{"tb1qywvazres587w9wyy8uw03q8j9ek6gc9crwx4jvhqcmew4xzsvqcq3jjdja":0.01000000}]'
```

### Safety warning about batch transactions

As mentioned before, the PSBT channel funding flow works by pausing the funding
negotiation with the remote peer directly after the multisig keys have been
exchanged. That means, the channel isn't fully opened yet at the time the PSBT
is signed. This is fine for a single channel because the signed transaction is
only published after the counter-signed commitment transactions were exchanged
and the funds can be spent again by both parties.

When doing batch transactions, **publishing** the whole transaction with
multiple channel funding outputs **too early could lead to loss of funds**!

For example, let's say we want to open two channels. We call `openchannel --psbt`
two times, combine the funding addresses as shown above, verify the PSBT, sign
it and finally paste it into the terminal of the first command. `lnd` then goes
ahead and finishes the negotiations with peer 1. If successful, `lnd` publishes
the transaction. In the meantime we paste the same PSBT into the second terminal
window. But by now, the peer 2 for channel 2 has timed out our funding flow and
aborts the negotiation. Normally this would be fine, we would just not publish
the funding transaction. But in the batch case, channel 1 has already published
the transaction that contains both channel outputs. But because we never got a
signature from peer 2 to spend the funds now locked in a 2-of-2 multisig, the
fund are lost (unless peer 2 cooperates in a complicated, manual recovery
process).

### Use --no_publish for batch transactions

To mitigate the problem described in the section above, when open multiple
channels in one batch transaction, it is **imperative to use the
`--no_publish`** flag for each channel but the very last. This prevents the
full batch transaction to be published before each and every single channel has
fully completed its funding negotiation.

### Use the BatchOpenChannel RPC for safe batch channel funding

If `lnd`'s internal wallet should fund the batch channel open transaction then
the safest option is the `BatchOpenChannel` RPC (and its
`lncli batchopenchannel` counterpart).
The `BatchOpenChannel` RPC accepts a list of node pubkeys and amounts and will
try to atomically open channels in a single transaction to all of the nodes. If
any of the individual channel negotiations fails (for example because of a
minimum channel size not being met) then the whole batch is aborted and
lingering reservations/intents/pending channels are cleaned up.

**Example using the CLI**:

```shell
⛰  lncli batchopenchannel --sat_per_vbyte=5 '[{
    "node_pubkey": "02c95fd94d2a40e483e8a14be1625ad8a82263b37b6a32162170d8d4c13080bedb",
    "local_funding_amount": 500000,
    "private": true,
    "close_address": "2NCJnjD4CZ5JvmkEo1D3QfDM57GX62LUbep"
  }, {
    "node_pubkey": "032d57116b92b5f64f022271ebd5e9e23826c0f34ff5ae3e742ad329e0dc5ddff8",
    "local_funding_amount": 600000,
    "remote_csv_delay": 288
  }, {
    "node_pubkey": "03475f7b07f79672b9a1fd2a3a2350bc444980fe06eb3ae38b132c6f43f958947b",
    "local_funding_amount": 700000
  }, {
    "node_pubkey": "027f013b5cf6b7035744fd8d7d756e05675bf6e829bb75a80be5b9e8e641d20562",
    "local_funding_amount": 800000
  }]'
```

**NOTE**: You must be connected to each of the nodes you want to open channels
to before you run the command.
