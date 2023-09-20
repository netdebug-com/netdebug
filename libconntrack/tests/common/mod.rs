pub mod tonic_helpers {
    use tokio::io::DuplexStream;
    use tonic::transport::{Channel, Endpoint};
    use tower::service_fn;

    // A "fake" connection
    pub struct FakeConnection {
        pub server_stream: DuplexStream,
        pub client_channel: Channel,
    }
    pub async fn get_fake_connection() -> FakeConnection {
        // See https://github.com/hyperium/tonic/blob/master/examples/src/mock/mock.rs
        // For what all this black magic here does.
        let (client_stream, server_stream) = tokio::io::duplex(1024);

        let mut client_stream = Some(client_stream);
        let client_channel = Endpoint::try_from("http://[::]:12345")
            .unwrap()
            .connect_with_connector(service_fn(move |_: tonic::transport::Uri| {
                let client_stream = client_stream.take();
                async move {
                    if let Some(client_stream) = client_stream {
                        Ok(client_stream)
                    } else {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "Client already taken",
                        ))
                    }
                }
            }))
            .await
            .unwrap();

        FakeConnection {
            server_stream,
            client_channel,
        }
    }
}
