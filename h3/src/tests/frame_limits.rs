use std::{sync::Arc, time::Duration};

use assert_matches::assert_matches;
use bytes::{Bytes, BytesMut};
use futures_util::future::poll_fn;
use http::Request;

use crate::{
    client,
    error::{Code, ConnectionError, LocalError, StreamError},
    proto::{coding::Encode, frame::FrameType, stream::StreamType, varint::VarInt},
    server,
};

use super::Pair;

fn announce(ty: FrameType, length: u32) -> BytesMut {
    let mut header = BytesMut::new();
    ty.encode(&mut header);
    VarInt::from_u32(length).encode(&mut header);
    header
}

fn assert_local_limit(error: ConnectionError) {
    assert_matches!(
        error,
        ConnectionError::Local {
            error: LocalError::Application {
                code: Code::H3_EXCESSIVE_LOAD,
                ..
            }
        }
    );
}

fn assert_remote_limit(error: quinn::ConnectionError) {
    assert_matches!(error, quinn::ConnectionError::ApplicationClosed(close)
        if close.error_code.into_inner() == Code::H3_EXCESSIVE_LOAD.value());
}

#[tokio::test]
async fn server_rejects_announced_request_headers_before_payload() {
    let mut pair = Pair::default();
    let mut endpoint = pair.server();
    let sender = async {
        let connection = pair.client_inner().await;
        let (mut send, _recv) = connection.open_bi().await.unwrap();
        send.write_all(&announce(FrameType::HEADERS, 65))
            .await
            .unwrap();
        // Do not send the body or FIN: the frame header must suffice to reject it.
        assert_remote_limit(connection.closed().await);
    };
    let receiver = async {
        let mut connection = server::builder()
            .max_field_section_size(16 * 1024)
            .max_non_data_frame_size(64)
            .build(endpoint.next().await)
            .await
            .unwrap();
        let request = connection.accept().await.unwrap().unwrap();
        let result = request.resolve_request().await.map(|_| ());
        assert_matches!(
            result,
            Err(StreamError::ConnectionError(ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_EXCESSIVE_LOAD,
                    ..
                }
            }))
        );
        assert_local_limit(connection.accept().await.err().unwrap());
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(sender, receiver);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn incomplete_headers_are_rejected_despite_small_quic_windows() {
    // This test uses only pre-existing APIs, including max_field_section_size,
    // and can be applied unchanged to the original implementation.
    let mut pair = Pair::default();
    Arc::get_mut(&mut pair.config)
        .unwrap()
        .stream_receive_window(quinn::VarInt::from_u32(16 * 1024))
        .receive_window(quinn::VarInt::from_u32(16 * 1024));
    let mut endpoint = pair.server();
    let (written_tx, written_rx) = tokio::sync::oneshot::channel();
    let sender = async {
        let connection = pair.client_inner().await;
        // Limit local queuing too, so write_all cannot succeed merely by
        // queuing the entire payload behind the peer's receive window.
        connection.set_send_window(16 * 1024);
        let (mut send, _recv) = connection.open_bi().await.unwrap();
        send.write_all(&announce(FrameType::HEADERS, 256 * 1024))
            .await
            .unwrap();
        let written = send.write_all(&vec![0_u8; 128 * 1024]).await.is_ok();
        let _ = written_tx.send(written);
        assert_remote_limit(connection.closed().await);
    };
    let receiver = async {
        let mut connection = server::builder()
            .max_field_section_size(8 * 1024)
            .build(endpoint.next().await)
            .await
            .unwrap();
        let request = connection.accept().await.unwrap().unwrap();
        tokio::select! {
            result = request.resolve_request() => {
                assert_matches!(result.map(|_| ()), Err(StreamError::ConnectionError(ConnectionError::Local {
                    error: LocalError::Application { code: Code::H3_EXCESSIVE_LOAD, .. }
                })));
            }
            written = written_rx => {
                panic!("incomplete HEADERS payload admitted beyond the 8 KiB field limit and 16 KiB QUIC windows; 128 KiB write succeeded: {:?}", written);
            }
        }
        assert_local_limit(connection.accept().await.err().unwrap());
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(sender, receiver);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn server_rejects_announced_control_frame_before_payload() {
    let mut pair = Pair::default();
    let mut endpoint = pair.server();
    let sender = async {
        let connection = pair.client_inner().await;
        let mut send = connection.open_uni().await.unwrap();
        let mut header = BytesMut::new();
        StreamType::CONTROL.encode(&mut header);
        header.extend_from_slice(&announce(FrameType::SETTINGS, 65));
        send.write_all(&header).await.unwrap();
        assert_remote_limit(connection.closed().await);
    };
    let receiver = async {
        let mut connection = server::builder()
            .max_non_data_frame_size(64)
            .build(endpoint.next().await)
            .await
            .unwrap();
        assert_local_limit(connection.accept().await.err().unwrap());
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(sender, receiver);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn client_clone_and_split_preserve_response_frame_limit() {
    let mut pair = Pair::default();
    let endpoint = pair.server();
    let sender = async {
        let connection = endpoint.endpoint.accept().await.unwrap().await.unwrap();
        let (mut send, _recv) = connection.accept_bi().await.unwrap();
        send.write_all(&announce(FrameType::HEADERS, 65))
            .await
            .unwrap();
        assert_remote_limit(connection.closed().await);
    };
    let receiver = async {
        let (mut driver, client) = client::builder()
            .max_field_section_size(16 * 1024)
            .max_non_data_frame_size(64)
            .build::<_, _, Bytes>(pair.client().await)
            .await
            .unwrap();
        let mut cloned = client.clone();
        let request = cloned
            .send_request(Request::get("https://localhost/").body(()).unwrap())
            .await
            .unwrap();
        let (_send, mut recv) = request.split();
        assert_matches!(
            recv.recv_response().await,
            Err(StreamError::ConnectionError(ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_EXCESSIVE_LOAD,
                    ..
                }
            }))
        );
        assert_local_limit(poll_fn(|cx| driver.poll_close(cx)).await);
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(sender, receiver);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn client_rejects_announced_control_frame_before_payload() {
    let mut pair = Pair::default();
    let endpoint = pair.server();
    let sender = async {
        let connection = endpoint.endpoint.accept().await.unwrap().await.unwrap();
        let mut send = connection.open_uni().await.unwrap();
        let mut header = BytesMut::new();
        StreamType::CONTROL.encode(&mut header);
        header.extend_from_slice(&announce(FrameType::SETTINGS, 65));
        send.write_all(&header).await.unwrap();
        assert_remote_limit(connection.closed().await);
    };
    let receiver = async {
        let (mut driver, _client) = client::builder()
            .max_non_data_frame_size(64)
            .build::<_, _, Bytes>(pair.client().await)
            .await
            .unwrap();
        assert_local_limit(poll_fn(|cx| driver.poll_close(cx)).await);
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(sender, receiver);
    })
    .await
    .unwrap();
}
