use std::task::{Context, Poll};

use bytes::Buf;

#[cfg(feature = "tracing")]
use tracing::trace;

use crate::error::Code;
use crate::proto::frame::SettingsError;
use crate::proto::push::InvalidPushId;
use crate::quic::{InvalidStreamId, StreamErrorIncoming};
use crate::stream::{BufRecvStream, WriteBuf};
use crate::{
    buf::BufList,
    proto::{
        frame::{self, Frame, PayloadLen},
        stream::StreamId,
    },
    quic::{BidiStream, RecvStream, SendStream},
};

/// Decodes Frames from the underlying QUIC stream
pub struct FrameStream<S, B> {
    pub stream: BufRecvStream<S, B>,
    // Already read data from the stream
    decoder: FrameDecoder,
    remaining_data: usize,
}

impl<S, B> FrameStream<S, B> {
    pub fn new(stream: BufRecvStream<S, B>) -> Self {
        Self {
            stream,
            decoder: FrameDecoder::default(),
            remaining_data: 0,
        }
    }

    /// Sets the maximum encoded payload size buffered for a non-DATA frame.
    /// DATA and WebTransport stream payloads are not subject to this limit.
    pub fn with_max_non_data_frame_size(mut self, max: usize) -> Self {
        self.decoder.max_non_data_frame_size = max;
        self.decoder.expected = None;
        self
    }

    /// Unwraps the Framed streamer and returns the underlying stream **without** data loss for
    /// partially received/read frames.
    pub fn into_inner(self) -> BufRecvStream<S, B> {
        self.stream
    }
}

impl<S, B> FrameStream<S, B>
where
    S: crate::quic::Is0rtt,
{
    /// Checks if the stream was opened in 0-RTT mode
    pub(crate) fn is_0rtt(&self) -> bool {
        self.stream.is_0rtt()
    }
}

impl<S, B> FrameStream<S, B>
where
    S: RecvStream,
{
    /// Polls the stream for the next frame header
    ///
    /// When a frame header is received use `poll_data` to retrieve the frame's data.
    pub fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Frame<PayloadLen>>, FrameStreamError>> {
        assert!(
            self.remaining_data == 0,
            "There is still data to read, please call poll_data() until it returns None."
        );

        loop {
            match self.decoder.decode(self.stream.buf_mut())? {
                Some(Frame::Data(PayloadLen(len))) => {
                    self.remaining_data = len;
                    return Poll::Ready(Ok(Some(Frame::Data(PayloadLen(len)))));
                }
                frame @ Some(Frame::WebTransportStream(_)) => {
                    self.remaining_data = usize::MAX;
                    return Poll::Ready(Ok(frame));
                }
                Some(frame) => return Poll::Ready(Ok(Some(frame))),
                None => {}
            }

            match self.try_recv(cx)? {
                // Received a chunk but the frame is incomplete, poll until we get `Pending`.
                Poll::Ready(false) => continue,
                Poll::Pending => return Poll::Pending,
                Poll::Ready(true) => {
                    if self.stream.buf_mut().has_remaining() {
                        // Reached the end of receive stream, but there is still some data:
                        // The frame is incomplete.
                        return Poll::Ready(Err(FrameStreamError::UnexpectedEnd));
                    } else {
                        return Poll::Ready(Ok(None));
                    }
                }
            }
        }
    }

    /// Retrieves the next piece of data in an incoming data packet or webtransport stream
    ///
    ///
    /// WebTransport bidirectional payload has no finite length and is processed until the end of the stream.
    pub fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<impl Buf>, FrameStreamError>> {
        if self.remaining_data == 0 {
            return Poll::Ready(Ok(None));
        };

        let end = match self.try_recv(cx) {
            Poll::Ready(Ok(end)) => end,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => false,
        };
        let data = self.stream.buf_mut().take_chunk(self.remaining_data);

        match (data, end) {
            (None, true) => Poll::Ready(Ok(None)),
            (None, false) => Poll::Pending,
            (Some(d), true)
                if d.remaining() < self.remaining_data
                    && !self.stream.buf_mut().has_remaining() =>
            {
                Poll::Ready(Err(FrameStreamError::UnexpectedEnd))
            }
            (Some(d), _) => {
                self.remaining_data -= d.remaining();
                Poll::Ready(Ok(Some(d)))
            }
        }
    }

    /// Stops the underlying stream with the provided error code
    pub(crate) fn stop_sending(&mut self, error_code: Code) {
        self.stream.stop_sending(error_code.into());
    }

    pub(crate) fn has_data(&self) -> bool {
        self.remaining_data != 0
    }

    pub(crate) fn is_eos(&self) -> bool {
        self.stream.is_eos() && !self.stream.buf().has_remaining()
    }

    fn try_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, FrameStreamError>> {
        if self.stream.is_eos() {
            return Poll::Ready(Ok(true));
        }
        match self.stream.poll_read(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(FrameStreamError::Quic(e))),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(eos)) => Poll::Ready(Ok(eos)),
        }
    }

    pub fn id(&self) -> StreamId {
        self.stream.recv_id()
    }
}

impl<T, B> SendStream<B> for FrameStream<T, B>
where
    T: SendStream<B>,
    B: Buf,
{
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.stream.poll_ready(cx)
    }

    fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
        self.stream.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.stream.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.stream.reset(reset_code)
    }

    fn send_id(&self) -> StreamId {
        self.stream.send_id()
    }
}

impl<S, B> FrameStream<S, B>
where
    S: BidiStream<B>,
    B: Buf,
{
    pub(crate) fn split(self) -> (FrameStream<S::SendStream, B>, FrameStream<S::RecvStream, B>) {
        let (send, recv) = self.stream.split();
        (
            FrameStream {
                stream: send,
                decoder: FrameDecoder::default(),
                remaining_data: 0,
            },
            FrameStream {
                stream: recv,
                decoder: self.decoder,
                remaining_data: self.remaining_data,
            },
        )
    }
}

pub struct FrameDecoder {
    expected: Option<usize>,
    max_non_data_frame_size: usize,
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self {
            expected: None,
            max_non_data_frame_size: crate::config::DEFAULT_MAX_NON_DATA_FRAME_SIZE,
        }
    }
}

impl FrameDecoder {
    fn decode<B: Buf>(
        &mut self,
        src: &mut BufList<B>,
    ) -> Result<Option<Frame<PayloadLen>>, FrameStreamError> {
        // Decode in a loop since we ignore unknown frames, and there may be
        // other frames already in our BufList.
        loop {
            if !src.has_remaining() {
                return Ok(None);
            }

            if let Some(min) = self.expected {
                if src.remaining() < min {
                    return Ok(None);
                }
            }

            let (pos, decoded) = {
                let mut cur = src.cursor();
                let decoded = Frame::decode_with_limit(&mut cur, self.max_non_data_frame_size);
                (cur.position(), decoded)
            };

            match decoded {
                Err(frame::FrameError::UnknownFrame(_ty)) => {
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
                    //# Frames of unknown types (Section 9), including reserved frames
                    //# (Section 7.2.8) MAY be sent on a request or push stream before,
                    //# after, or interleaved with other frames described in this section.
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.8
                    //# Endpoints MUST
                    //# NOT consider these frames to have any meaning upon receipt.
                    #[cfg(feature = "tracing")]
                    trace!("ignore unknown frame type {:#x}", _ty);

                    src.advance(pos);
                    self.expected = None;
                    continue;
                }
                Err(frame::FrameError::Incomplete(min)) => {
                    self.expected = Some(min);
                    return Ok(None);
                }
                Ok(frame) => {
                    src.advance(pos);
                    self.expected = None;
                    return Ok(Some(frame));
                }
                // -------------- Map the error Values --------------
                Err(frame::FrameError::TooLarge { length, max }) => {
                    return Err(FrameStreamError::Proto(FrameProtocolError::TooLarge {
                        length,
                        max,
                    }));
                }
                Err(frame::FrameError::InvalidStreamId(e)) => {
                    return Err(FrameStreamError::Proto(
                        FrameProtocolError::InvalidStreamId(e),
                    ));
                }
                Err(frame::FrameError::InvalidPushId(e)) => {
                    return Err(FrameStreamError::Proto(FrameProtocolError::InvalidPushId(
                        e,
                    )));
                }
                Err(frame::FrameError::Settings(e)) => {
                    return Err(FrameStreamError::Proto(FrameProtocolError::Settings(e)));
                }
                Err(frame::FrameError::UnsupportedFrame(ty)) => {
                    return Err(FrameStreamError::Proto(FrameProtocolError::ForbiddenFrame(
                        ty,
                    )));
                }
                Err(frame::FrameError::InvalidFrameValue) => {
                    return Err(FrameStreamError::Proto(
                        FrameProtocolError::InvalidFrameValue,
                    ));
                }
                Err(frame::FrameError::Malformed) => {
                    return Err(FrameStreamError::Proto(FrameProtocolError::Malformed));
                }
            }
        }
    }
}

#[derive(Debug)]
/// Errors that can occur while decoding frames
pub enum FrameStreamError {
    Proto(FrameProtocolError),
    Quic(StreamErrorIncoming),
    UnexpectedEnd,
}

#[derive(Debug, PartialEq)]
/// Protocol specific errors that can occur while decoding frames in a stream
pub enum FrameProtocolError {
    TooLarge { length: u64, max: usize },
    Malformed,
    ForbiddenFrame(u64), // Known (http2) frames that should generate an error
    InvalidFrameValue,
    Settings(SettingsError),
    InvalidStreamId(InvalidStreamId),
    InvalidPushId(InvalidPushId),
}

#[cfg(test)]
mod tests {
    use super::*;

    use assert_matches::assert_matches;
    use bytes::{BufMut, Bytes, BytesMut};
    use futures_util::future::poll_fn;
    use std::{cell::Cell, collections::VecDeque, rc::Rc};

    use crate::proto::{coding::Encode, frame::FrameType, varint::VarInt};

    // Decoder

    #[test]
    fn one_frame() {
        let mut buf = BytesMut::with_capacity(16);
        Frame::headers(&b"salut"[..]).encode_with_payload(&mut buf);
        let mut buf = BufList::from(buf);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(Some(Frame::Headers(_))));
    }

    #[test]
    fn incomplete_frame() {
        let frame = Frame::headers(&b"salut"[..]);

        let mut buf = BytesMut::with_capacity(16);
        frame.encode(&mut buf);
        buf.truncate(buf.len() - 1);
        let mut buf = BufList::from(buf);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(None));
    }

    #[test]
    fn header_spread_multiple_buf() {
        let mut buf = BytesMut::with_capacity(16);
        Frame::headers(&b"salut"[..]).encode_with_payload(&mut buf);
        let mut buf_list = BufList::new();
        // Cut buffer between type and length
        buf_list.push(&buf[..1]);
        buf_list.push(&buf[1..]);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf_list), Ok(Some(Frame::Headers(_))));
    }

    #[test]
    fn varint_spread_multiple_buf() {
        let mut buf = BytesMut::with_capacity(16);
        Frame::headers("salut".repeat(1024)).encode_with_payload(&mut buf);

        let mut buf_list = BufList::new();
        // Cut buffer in the middle of length's varint
        buf_list.push(&buf[..2]);
        buf_list.push(&buf[2..]);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf_list), Ok(Some(Frame::Headers(_))));
    }

    #[test]
    fn two_frames_then_incomplete() {
        let mut buf = BytesMut::with_capacity(64);
        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        Frame::Data(&b"body"[..]).encode_with_payload(&mut buf);
        Frame::headers(&b"trailer"[..]).encode_with_payload(&mut buf);

        buf.truncate(buf.len() - 1);
        let mut buf = BufList::from(buf);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(Some(Frame::Headers(_))));
        assert_matches!(
            decoder.decode(&mut buf),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_matches!(decoder.decode(&mut buf), Ok(None));
    }

    // FrameStream

    #[tokio::test]
    async fn oversized_incomplete_headers_do_not_buffer_the_announced_payload() {
        // Keep this regression independent of new configuration/error APIs so
        // it can also be run against the original decoder.
        let mut header = BytesMut::new();
        FrameType::HEADERS.encode(&mut header);
        VarInt::try_from(256 * 1024_u64)
            .unwrap()
            .encode(&mut header);
        let header_len = header.len();
        let mut recv = FakeRecv::default();
        recv.chunk(header.freeze());
        for _ in 0..128 {
            recv.chunk(Bytes::from(vec![0_u8; 1024]));
        }
        let polls = recv.poll_count.clone();
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        let result = poll_fn(|cx| stream.poll_next(cx)).await;
        let buffered = stream.stream.buf().remaining();
        assert!(
            matches!(result, Err(FrameStreamError::Proto(_))),
            "expected rejection from the frame header, got {:?}; retained {} bytes after {} transport polls",
            result, buffered, polls.get(),
        );
        assert_eq!(polls.get(), 1);
        assert_eq!(buffered, header_len);
    }

    #[test]
    fn non_data_frame_lengths_are_checked_before_payload_arrives() {
        for ty in [
            FrameType::HEADERS,
            FrameType::SETTINGS,
            FrameType::PUSH_PROMISE,
            FrameType::GOAWAY,
            FrameType::CANCEL_PUSH,
            FrameType::MAX_PUSH_ID,
            FrameType::RESERVED,
        ] {
            let mut header = BytesMut::new();
            ty.encode(&mut header);
            VarInt::MAX.encode(&mut header);
            let mut buf = BufList::from(header);
            let mut decoder = FrameDecoder::default();
            assert_matches!(
                decoder.decode(&mut buf),
                Err(FrameStreamError::Proto(FrameProtocolError::TooLarge { .. }))
            );
        }
    }

    #[test]
    fn split_type_and_length_varints_are_bounded_as_soon_as_complete() {
        let mut header = BytesMut::new();
        FrameType::RESERVED.encode(&mut header);
        VarInt::MAX.encode(&mut header);
        let mut buf = BufList::new();
        let mut decoder = FrameDecoder::default();
        for byte in &header[..header.len() - 1] {
            buf.push(Bytes::copy_from_slice(&[*byte]));
            assert_matches!(decoder.decode(&mut buf), Ok(None));
        }
        buf.push(Bytes::copy_from_slice(&header[header.len() - 1..]));
        assert_matches!(
            decoder.decode(&mut buf),
            Err(FrameStreamError::Proto(FrameProtocolError::TooLarge { .. }))
        );
        assert_eq!(buf.remaining(), header.len());
    }

    #[tokio::test]
    async fn configured_limit_accepts_boundary_and_rejects_trailers_above_it() {
        let mut recv = FakeRecv::default();
        let mut headers = BytesMut::new();
        Frame::headers(&b"12345"[..]).encode_with_payload(&mut headers);
        Frame::Data(&b""[..]).encode_with_payload(&mut headers);
        FrameType::HEADERS.encode(&mut headers);
        VarInt::from_u32(6).encode(&mut headers);
        recv.chunk(headers.freeze());
        let mut stream: FrameStream<_, ()> =
            FrameStream::new(BufRecvStream::new(recv)).with_max_non_data_frame_size(5);
        assert_matches!(
            poll_fn(|cx| stream.poll_next(cx)).await,
            Ok(Some(Frame::Headers(_)))
        );
        assert_matches!(
            poll_fn(|cx| stream.poll_next(cx)).await,
            Ok(Some(Frame::Data(PayloadLen(0))))
        );
        assert_matches!(
            poll_fn(|cx| stream.poll_next(cx)).await,
            Err(FrameStreamError::Proto(FrameProtocolError::TooLarge {
                length: 6,
                max: 5
            }))
        );
    }

    #[tokio::test]
    async fn configurable_limit_can_accept_larger_encoded_headers() {
        let mut bytes = BytesMut::new();
        Frame::headers(Bytes::from(vec![0_u8; 128 * 1024])).encode_with_payload(&mut bytes);
        let mut recv = FakeRecv::default();
        recv.chunk(bytes.freeze());
        let mut stream: FrameStream<_, ()> =
            FrameStream::new(BufRecvStream::new(recv)).with_max_non_data_frame_size(128 * 1024);
        assert_matches!(poll_fn(|cx| stream.poll_next(cx)).await, Ok(Some(Frame::Headers(headers))) if headers.len() == 128 * 1024);
    }

    #[test]
    fn data_and_webtransport_prefixes_are_exempt_from_buffered_frame_limit() {
        let mut data = BytesMut::new();
        FrameType::DATA.encode(&mut data);
        VarInt::from_u32(1024 * 1024).encode(&mut data);
        let mut decoder = FrameDecoder {
            max_non_data_frame_size: 0,
            ..FrameDecoder::default()
        };
        assert_matches!(
            decoder.decode(&mut BufList::from(data)),
            Ok(Some(Frame::Data(PayloadLen(1_048_576))))
        );

        let mut webtransport = BytesMut::new();
        FrameType::WEBTRANSPORT_BI_STREAM.encode(&mut webtransport);
        VarInt::from_u32(1024 * 1024).encode(&mut webtransport);
        assert_matches!(
            decoder.decode(&mut BufList::from(webtransport)),
            Ok(Some(Frame::WebTransportStream(_)))
        );
    }

    #[test]
    fn frame_size_failure_uses_excessive_load_connection_error() {
        let error = crate::error::internal_error::InternalConnectionError::got_frame_error(
            FrameProtocolError::TooLarge {
                length: 128 * 1024,
                max: 64 * 1024,
            },
        );
        assert_eq!(error.code, Code::H3_EXCESSIVE_LOAD);
    }

    macro_rules! assert_poll_matches {
        ($poll_fn:expr, $match:pat) => {
            assert_matches!(
                poll_fn($poll_fn).await,
                $match
            );
        };
        ($poll_fn:expr, $match:pat if $cond:expr ) => {
            assert_matches!(
                poll_fn($poll_fn).await,
                $match if $cond
            );
        }
    }

    #[tokio::test]
    async fn poll_full_request() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        Frame::Data(&b"body"[..]).encode_with_payload(&mut buf);
        Frame::headers(&b"trailer"[..]).encode_with_payload(&mut buf);
        recv.chunk(buf.freeze());

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if b.remaining() == 4
        );
        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
    }

    #[tokio::test]
    async fn poll_next_applies_backpressure_before_reading_more_chunks() {
        const CHUNK_COUNT: usize = 64;
        const FRAMES_PER_CHUNK: usize = 16;
        const FRAME_PAYLOAD_SIZE: usize = 1024;

        let mut encoded_chunk = BytesMut::new();
        let payload = Bytes::from(vec![0_u8; FRAME_PAYLOAD_SIZE]);
        for _ in 0..FRAMES_PER_CHUNK {
            Frame::headers(payload.clone()).encode_with_payload(&mut encoded_chunk);
        }
        let encoded_chunk = encoded_chunk.freeze();
        let max_buffered = encoded_chunk.len();

        let mut recv = FakeRecv::default();
        for _ in 0..CHUNK_COUNT {
            recv.chunk(encoded_chunk.clone());
        }
        let transport_polls = recv.poll_count.clone();

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        // Model a consumer that processes one frame per wake while the
        // transport can provide chunks containing many complete frames.
        for _ in 0..CHUNK_COUNT {
            assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
        }

        let buffered = stream.stream.buf().remaining();
        assert!(
            buffered <= max_buffered,
            "frame buffering grew past one transport chunk: {buffered} > {max_buffered}"
        );
        assert_eq!(
            transport_polls.get(),
            CHUNK_COUNT.div_ceil(FRAMES_PER_CHUNK),
            "transport was polled while complete frames were still buffered"
        );
    }

    #[tokio::test]
    async fn poll_next_incomplete_frame() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        let mut buf = buf.freeze();
        recv.chunk(buf.split_to(buf.len() - 1));
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Err(FrameStreamError::UnexpectedEnd)
        );
    }

    #[tokio::test]
    #[should_panic(
        expected = "There is still data to read, please call poll_data() until it returns None"
    )]
    async fn poll_next_reamining_data() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );

        // There is still data to consume, poll_next should panic
        let _ = poll_fn(|cx| stream.poll_next(cx)).await;
    }

    #[tokio::test]
    async fn poll_data_split() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        // Body is split into two bufs
        Frame::Data(Bytes::from("body")).encode_with_payload(&mut buf);

        let mut buf = buf.freeze();
        recv.chunk(buf.split_to(buf.len() - 2));
        recv.chunk(buf);
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        // We get the total size of data about to be received
        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );

        // Then we get parts of body, chunked as they arrived
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if b.remaining() == 2
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if b.remaining() == 2
        );
    }

    #[tokio::test]
    async fn poll_data_unexpected_end() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        // Truncated body
        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        buf.put_slice(&b"b"[..]);
        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Err(FrameStreamError::UnexpectedEnd)
        );
    }

    #[tokio::test]
    async fn poll_data_ignores_unknown_frames() {
        use crate::proto::varint::BufMutExt as _;

        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        // grease a lil
        crate::proto::frame::FrameType::grease().encode(&mut buf);
        buf.write_var(0);

        // grease with some data
        crate::proto::frame::FrameType::grease().encode(&mut buf);
        buf.write_var(6);
        buf.put_slice(b"grease");

        // Body
        Frame::Data(Bytes::from("body")).encode_with_payload(&mut buf);

        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"body"
        );
    }

    #[tokio::test]
    async fn poll_data_eos_but_buffered_data() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        buf.put_slice(&b"bo"[..]);
        recv.chunk(buf.clone().freeze());

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );

        buf.truncate(0);
        buf.put_slice(&b"dy"[..]);
        stream.stream.buf_mut().push_bytes(&mut buf.freeze());

        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"bo"
        );

        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"dy"
        );
    }

    // Helpers

    #[derive(Default)]
    struct FakeRecv {
        chunks: VecDeque<Bytes>,
        poll_count: Rc<Cell<usize>>,
    }

    impl FakeRecv {
        fn chunk(&mut self, buf: Bytes) -> &mut Self {
            self.chunks.push_back(buf);
            self
        }
    }

    impl RecvStream for FakeRecv {
        type Buf = Bytes;

        fn poll_data(
            &mut self,
            _: &mut Context<'_>,
        ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
            self.poll_count.set(self.poll_count.get() + 1);
            Poll::Ready(Ok(self.chunks.pop_front()))
        }

        fn stop_sending(&mut self, _: u64) {
            unimplemented!()
        }

        fn recv_id(&self) -> StreamId {
            unimplemented!()
        }
    }

    fn to_bytes(
        x: Poll<Result<Option<impl Buf>, FrameStreamError>>,
    ) -> Poll<Result<Option<Bytes>, FrameStreamError>> {
        x.map(|b| b.map(|b| b.map(|mut b| b.copy_to_bytes(b.remaining()))))
    }
}
