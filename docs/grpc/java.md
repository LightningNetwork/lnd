
# How to write a Java gRPC client for the Lightning Network Daemon

This section enumerates what you need to do to write a client that communicates
with lnd in Java. We'll be using Maven as our build tool.

### Prerequisites
 - Maven
 - running lnd
 - running btcd

### Setup and Installation
#### Project Structure
```text
.
├── pom.xml
└── src
    ├── main
       ├── java
       │   └── Main.java
       ├── proto
          ├── google
          │   └── api
          │       ├── annotations.proto
          │       └── http.proto
          └── lnrpc
              └── lightning.proto

```
Note the ***proto*** folder, where all the proto files are kept.

 - [rpc.proto](https://github.com/lightningnetwork/lnd/blob/master/lnrpc/rpc.proto)
 - [annotations.proto](https://github.com/grpc-ecosystem/grpc-gateway/blob/master/third_party/googleapis/google/api/annotations.proto)
 - [http.proto](https://github.com/grpc-ecosystem/grpc-gateway/blob/master/third_party/googleapis/google/api/http.proto)

#### pom.xml
```xml
<properties>
    <grpc.version>1.8.0</grpc.version>
</properties>    
```
The following dependencies are required.
```xml
<dependencies>
    <dependency>
        <groupId>io.grpc</groupId>
        <artifactId>grpc-netty</artifactId>
        <version>${grpc.version}</version>
    </dependency>
    <dependency>
        <groupId>io.grpc</groupId>
        <artifactId>grpc-protobuf</artifactId>
        <version>${grpc.version}</version>
    </dependency>
    <dependency>
        <groupId>io.grpc</groupId>
        <artifactId>grpc-stub</artifactId>
        <version>${grpc.version}</version>
    </dependency>
    <dependency>
        <groupId>io.netty</groupId>
        <artifactId>netty-tcnative-boringssl-static</artifactId>
        <version>2.0.7.Final</version>
    </dependency>
    <dependency>
        <groupId>commons-codec</groupId>
        <artifactId>commons-codec</artifactId>
        <version>1.11</version>
    </dependency>
</dependencies>
```
In the build section,  we'll need to configure the following things :
```xml
<build>
    <extensions>
        <extension>
            <groupId>kr.motd.maven</groupId>
            <artifactId>os-maven-plugin</artifactId>
            <version>1.5.0.Final</version>
        </extension>
    </extensions>
    <plugins>
        <plugin>
            <groupId>org.xolstice.maven.plugins</groupId>
            <artifactId>protobuf-maven-plugin</artifactId>
            <version>0.5.0</version>
            <configuration>
                <protocArtifact>com.google.protobuf:protoc:3.4.0:exe:${os.detected.classifier}</protocArtifact>
                <pluginId>grpc-java</pluginId>
                <pluginArtifact>io.grpc:protoc-gen-grpc-java:${grpc.version}:exe:${os.detected.classifier}</pluginArtifact>
            </configuration>
            <executions>
                <execution>
                    <goals>
                        <goal>compile</goal>
                        <goal>compile-custom</goal>
                    </goals>
                </execution>
            </executions>
        </plugin>
    </plugins>
</build>
```
#### Main.java
```java
import io.grpc.Attributes;
import io.grpc.CallCredentials;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.Status;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NettyChannelBuilder;
import io.netty.handler.ssl.SslContext;
import lnrpc.LightningGrpc;
import lnrpc.LightningGrpc.LightningBlockingStub;
import lnrpc.Rpc.GetInfoRequest;
import lnrpc.Rpc.GetInfoResponse;
import org.apache.commons.codec.binary.Hex;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.concurrent.Executor;

public class Main {
  static class MacaroonCallCredential implements CallCredentials {
    private final String macaroon;

    MacaroonCallCredential(String macaroon) {
      this.macaroon = macaroon;
    }

    public void thisUsesUnstableApi() {}

    public void applyRequestMetadata(
        MethodDescriptor < ? , ? > methodDescriptor,
        Attributes attributes,
        Executor executor,
        final MetadataApplier metadataApplier
    ) {
      String authority = attributes.get(ATTR_AUTHORITY);
      System.out.println(authority);
      executor.execute(new Runnable() {
        public void run() {
          try {
            Metadata headers = new Metadata();
            Metadata.Key < String > macaroonKey = Metadata.Key.of("macaroon", Metadata.ASCII_STRING_MARSHALLER);
            headers.put(macaroonKey, macaroon);
            metadataApplier.apply(headers);
          } catch (Throwable e) {
            metadataApplier.fail(Status.UNAUTHENTICATED.withCause(e));
          }
        }
      });
    }
  }

  private static final String CERT_PATH = "/Users/user/Library/Application Support/Lnd/tls.cert";
  private static final String MACAROON_PATH = "/Users/user/Library/Application Support/Lnd/data/chain/bitcoin/simnet/admin.macaroon";
  private static final String HOST = "localhost";
  private static final int PORT = 10009;

  public static void main(String...args) throws IOException {
    SslContext sslContext = GrpcSslContexts.forClient().trustManager(new File(CERT_PATH)).build();
    NettyChannelBuilder channelBuilder = NettyChannelBuilder.forAddress(HOST, PORT);
    ManagedChannel channel = channelBuilder.sslContext(sslContext).build();

    String macaroon =
        Hex.encodeHexString(
            Files.readAllBytes(Paths.get(MACAROON_PATH))
        );

    LightningBlockingStub stub = LightningGrpc
        .newBlockingStub(channel)
        .withCallCredentials(new MacaroonCallCredential(macaroon));


    GetInfoResponse response = stub.getInfo(GetInfoRequest.getDefaultInstance());
    System.out.println(response.getIdentityPubkey());
  }
}
```
#### Running the example
Execute the following command in the directory where the **pom.xml** file is located.
```shell
⛰  mvn compile exec:java -Dexec.mainClass="Main" -Dexec.cleanupDaemonThreads=false
```
##### Sample output
```text
[INFO] Scanning for projects...
[INFO] ------------------------------------------------------------------------
[INFO] Detecting the operating system and CPU architecture
[INFO] ------------------------------------------------------------------------
[INFO] os.detected.name: osx
[INFO] os.detected.arch: x86_64
[INFO] os.detected.version: 10.13
[INFO] os.detected.version.major: 10
[INFO] os.detected.version.minor: 13
[INFO] os.detected.classifier: osx-x86_64
[INFO]
[INFO] ------------------------------------------------------------------------
[INFO] Building lightning-client 0.0.1-SNAPSHOT
[INFO] ------------------------------------------------------------------------
[INFO]
[INFO] --- protobuf-maven-plugin:0.5.0:compile (default) @ lightning-client ---
[INFO] Compiling 3 proto file(s) to /Users/user/Documents/Projects/lightningclient/target/generated-sources/protobuf/java
[INFO]
[INFO] --- protobuf-maven-plugin:0.5.0:compile-custom (default) @ lightning-client ---
[INFO] Compiling 3 proto file(s) to /Users/user/Documents/Projects/lightningclient/target/generated-sources/protobuf/grpc-java
[INFO]
[INFO] --- maven-resources-plugin:2.6:resources (default-resources) @ lightning-client ---
[INFO] Using 'UTF-8' encoding to copy filtered resources.
[INFO] Copying 0 resource
[INFO] Copying 3 resources
[INFO] Copying 3 resources
[INFO]
[INFO] --- maven-compiler-plugin:3.1:compile (default-compile) @ lightning-client ---
[INFO] Changes detected - recompiling the module!
[INFO] Compiling 12 source files to /Users/user/Documents/Projects/lightningclient/target/classes
[INFO]
[INFO] --- exec-maven-plugin:1.6.0:java (default-cli) @ lightning-client ---
032562215c38dede6f1f2f262ff4c8db58a38ecf889e8e907eee8e4c320e0b5e81
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time: 7.408 s
[INFO] Finished at: 2018-01-13T19:05:49+01:00
[INFO] Final Memory: 30M/589M
[INFO] ------------------------------------------------------------------------
```

### Java proto options

There are 2 options available that can be used in the *lightning.proto* file :

* option java_multiple_files = true;
* option java_package = "network.lightning.rpc";
>The package you want to use for your generated Java classes. If no explicit java_package option is given in the .proto file, then by default the proto package (specified using the "package" keyword in the .proto file) will be used. However, proto packages generally do not make good Java packages since proto packages are not expected to start with reverse domain names. If not generating Java code, this option has no effect.
