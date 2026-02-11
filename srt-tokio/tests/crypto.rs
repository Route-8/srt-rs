use std::{
    convert::TryInto,
    io,
    time::{Duration, Instant},
};

use srt_protocol::settings::KeySettings;
use srt_tokio::{PassphraseResult, SrtListener, SrtSocket};

use assert_matches::assert_matches;
use bytes::Bytes;
use futures::{SinkExt, StreamExt, TryStreamExt};
use log::info;
use tokio::{select, spawn, time::sleep};

async fn test_crypto(size_listen: u16, size_call: u16, port: u16) {
    let sender = SrtSocket::builder()
        .encryption(size_listen, "password123")
        .listen_on(port);

    let local_addr = format!("127.0.0.1:{port}");

    let recvr = SrtSocket::builder()
        .encryption(size_call, "password123")
        .call(local_addr.as_str(), None);

    let t = spawn(async move {
        let mut sender = sender.await.unwrap();
        sender
            .send((Instant::now(), Bytes::from("Hello")))
            .await
            .unwrap();
        info!("Sent!");
        sleep(Duration::from_secs(1)).await;
        sender.close().await.unwrap();
        info!("Sender closed");
    });

    let mut recvr = recvr.await.unwrap();
    let (_, by) = recvr.try_next().await.unwrap().unwrap();
    info!("Got data");
    assert_eq!(&by[..], b"Hello");
    recvr.close().await.unwrap();
    info!("Receiver closed");
    t.await.unwrap();
}

#[tokio::test]
async fn crypto_exchange() {
    let _ = pretty_env_logger::try_init();

    test_crypto(16, 16, 2000).await;
    test_crypto(24, 24, 2001).await;
    test_crypto(32, 32, 2002).await;
}

#[tokio::test]
async fn key_size_mismatch() {
    test_crypto(32, 16, 2003).await;
    test_crypto(32, 0, 2004).await;
    test_crypto(0, 32, 2005).await;
}

#[tokio::test]
async fn bad_password_listen() {
    let listener = SrtSocket::builder()
        .encryption(16, "password1234")
        .listen_on(":3000");

    let caller = SrtSocket::builder()
        .encryption(16, "password123")
        .call("127.0.0.1:3000", None);

    let listener_fut = spawn(async move {
        listener.await.unwrap();
    });

    let res = caller.await;
    assert_matches!(res, Err(e) if e.kind() == io::ErrorKind::ConnectionRefused);

    assert_matches!(
        tokio::time::timeout(Duration::from_millis(100), listener_fut).await,
        Err(_)
    );
}

#[tokio::test]
async fn bad_password_rendezvous() {
    let a = SrtSocket::builder()
        .local_port(5301)
        .encryption(16, "password1234")
        .rendezvous("127.0.0.1:5300");

    let b = SrtSocket::builder()
        .encryption(16, "password123")
        .local_port(5300)
        .rendezvous("127.0.0.1:5301");

    let result = select!(
        r = a => r,
        r = b => r
    );

    assert_matches!(result, Err(e) if e.kind() == io::ErrorKind::ConnectionRefused);
}

#[tokio::test]
async fn passphrase_callback_simple() {
    let listener = SrtSocket::builder()
        .passphrase_callback(|stream_id, _| match stream_id {
            Some("channel1") => PassphraseResult::Passphrase("password123".into()),
            _ => PassphraseResult::Unauthorized,
        })
        .listen_on(":3010");

    let sender = spawn(async move {
        let mut sender = listener.await.unwrap();
        sender
            .send((Instant::now(), Bytes::from("Hello")))
            .await
            .unwrap();
        sender.close().await.unwrap();
    });

    let mut recvr = SrtSocket::builder()
        .encryption(16, "password123")
        .call("127.0.0.1:3010", Some("channel1"))
        .await
        .unwrap();
    let (_, by) = recvr.try_next().await.unwrap().unwrap();
    assert_eq!(&by[..], b"Hello");
    recvr.close().await.unwrap();
    sender.await.unwrap();
}

#[tokio::test]
async fn passphrase_callback_unauthorized() {
    let listener = SrtSocket::builder()
        .passphrase_callback(|_, _| PassphraseResult::Unauthorized)
        .listen_on(":3011");

    let listener_fut = spawn(async move {
        listener.await.unwrap();
    });

    let res = SrtSocket::builder()
        .encryption(16, "password123")
        .call("127.0.0.1:3011", Some("unknown"))
        .await;
    assert_matches!(res, Err(e) if e.kind() == io::ErrorKind::ConnectionRefused);

    assert_matches!(
        tokio::time::timeout(Duration::from_millis(100), listener_fut).await,
        Err(_)
    );
}

#[tokio::test]
async fn passphrase_callback_no_encryption() {
    let listener = SrtSocket::builder()
        .encryption(16, "password123")
        .passphrase_callback(|_, _| PassphraseResult::None)
        .listen_on(":3012");

    let sender = spawn(async move {
        let mut sender = listener.await.unwrap();
        sender
            .send((Instant::now(), Bytes::from("Hello")))
            .await
            .unwrap();
        sender.close().await.unwrap();
    });

    let mut recvr = SrtSocket::builder()
        .call("127.0.0.1:3012", Some("unencrypted"))
        .await
        .unwrap();
    let (_, by) = recvr.try_next().await.unwrap().unwrap();
    assert_eq!(&by[..], b"Hello");
    recvr.close().await.unwrap();
    sender.await.unwrap();
}

#[tokio::test]
async fn passphrase_callback_wrong_password() {
    let listener = SrtSocket::builder()
        .passphrase_callback(|_, _| PassphraseResult::Passphrase("password123".into()))
        .listen_on(":3013");

    let listener_fut = spawn(async move {
        listener.await.unwrap();
    });

    let res = SrtSocket::builder()
        .encryption(16, "wrongpassword")
        .call("127.0.0.1:3013", Some("channel1"))
        .await;
    assert_matches!(res, Err(e) if e.kind() == io::ErrorKind::ConnectionRefused);

    assert_matches!(
        tokio::time::timeout(Duration::from_millis(100), listener_fut).await,
        Err(_)
    );
}

#[tokio::test]
async fn passphrase_callback_invalid_password() {
    let listener = SrtSocket::builder()
        .passphrase_callback(|_, _| PassphraseResult::Passphrase("short".into()))
        .listen_on(":3014");

    let listener_fut = spawn(async move {
        listener.await.unwrap();
    });

    let res = SrtSocket::builder()
        .encryption(16, "password123")
        .call("127.0.0.1:3014", Some("channel1"))
        .await;
    assert_matches!(res, Err(e) if e.kind() == io::ErrorKind::ConnectionRefused);

    assert_matches!(
        tokio::time::timeout(Duration::from_millis(100), listener_fut).await,
        Err(_)
    );
}

#[tokio::test]
async fn passphrase_callback_multiplexed() {
    let listener = spawn(async move {
        let (_server, mut incoming) = SrtListener::builder()
            .passphrase_callback(|stream_id, _| match stream_id {
                Some("channel1") => PassphraseResult::Passphrase("password123".into()),
                Some("channel2") => PassphraseResult::Passphrase("password456".into()),
                _ => PassphraseResult::Unauthorized,
            })
            .bind("127.0.0.1:3015")
            .await
            .unwrap();

        for _ in 0..2 {
            let request = incoming.incoming().next().await.unwrap();
            let mut socket = request.accept(None).await.unwrap();
            socket
                .send((Instant::now(), Bytes::from("Hello")))
                .await
                .unwrap();
            sleep(Duration::from_millis(200)).await;
            socket.close().await.unwrap();
        }
    });

    let mut a = SrtSocket::builder()
        .encryption(16, "password123")
        .call("127.0.0.1:3015", Some("channel1"))
        .await
        .unwrap();
    let mut b = SrtSocket::builder()
        .encryption(16, "password456")
        .call("127.0.0.1:3015", Some("channel2"))
        .await
        .unwrap();

    let (_, a_data) = a.try_next().await.unwrap().unwrap();
    let (_, b_data) = b.try_next().await.unwrap().unwrap();
    assert_eq!(&a_data[..], b"Hello");
    assert_eq!(&b_data[..], b"Hello");
    a.close().await.unwrap();
    b.close().await.unwrap();
    listener.await.unwrap();
}

#[tokio::test]
async fn passphrase_callback_multiplexed_override() {
    let listener = spawn(async move {
        let (_server, mut incoming) = SrtListener::builder()
            .passphrase_callback(|_, _| PassphraseResult::Passphrase("wrongpassword".into()))
            .bind("127.0.0.1:3016")
            .await
            .unwrap();

        let request = incoming.incoming().next().await.unwrap();
        let key_size = request.key_size();
        let mut socket = request
            .accept(Some(KeySettings {
                key_size,
                passphrase: "password123".to_string().try_into().unwrap(),
            }))
            .await
            .unwrap();
        socket
            .send((Instant::now(), Bytes::from("Hello")))
            .await
            .unwrap();
        sleep(Duration::from_millis(200)).await;
        socket.close().await.unwrap();
    });

    let mut caller = SrtSocket::builder()
        .encryption(16, "password123")
        .call("127.0.0.1:3016", Some("override"))
        .await
        .unwrap();
    let (_, by) = caller.try_next().await.unwrap().unwrap();
    assert_eq!(&by[..], b"Hello");
    caller.close().await.unwrap();
    listener.await.unwrap();
}
