//! A collection of traits abstracting over Listeners and Streams.
use std::io::{self, Read, Write};
use std::net::{SocketAddr};
use std::option;

use rotor::mio::{Selector, Token, Evented, EventSet, PollOpt, TryAccept};
use rotor::mio::tcp::{TcpStream, TcpListener};

#[cfg(feature = "openssl")]
pub use self::openssl::{Openssl, OpensslStream};

#[cfg(feature = "security-framework")]
pub use self::security_framework::{SecureTransport, SecureTransportClient, SecureTransportServer};

/// A trait representing a socket transport that can be used in a Client or Server.
#[cfg(not(windows))]
pub trait Transport: Read + Write + Evented + ::vecio::Writev {
    /// Takes a socket error when event polling notices an `events.is_error()`.
    fn take_socket_error(&mut self) -> io::Result<()>;

    /// Returns if the this transport is blocked on read or write.
    ///
    /// By default, the user will declare whether they wish to wait on read
    /// or write events. However, some transports, such as those protected by
    /// TLS, may be blocked on reading before it can write, or vice versa.
    fn blocked(&self) -> Option<Blocked> {
        None
    }
}

/// A trait representing a socket transport that can be used in a Client or Server.
#[cfg(windows)]
pub trait Transport: Read + Write + Evented {
    /// Takes a socket error when event polling notices an `events.is_error()`.
    fn take_socket_error(&mut self) -> io::Result<()>;

    /// Returns if the this transport is blocked on read or write.
    ///
    /// By default, the user will declare whether they wish to wait on read
    /// or write events. However, some transports, such as those protected by
    /// TLS, may be blocked on reading before it can write, or vice versa.
    fn blocked(&self) -> Option<Blocked> {
        None
    }
}

/// Declares when a transport is blocked from any further action, until the
/// corresponding event has occured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Blocked {
    /// Blocked on reading
    Read,
    /// blocked on writing
    Write,
}


/// Accepts sockets asynchronously.
pub trait Accept: Evented {
    /// The transport type that is accepted.
    type Output: Transport;
    /// Accept a socket from the listener, if it doesn not block.
    fn accept(&self) -> io::Result<Option<Self::Output>>;
    /// Return the local `SocketAddr` of this listener.
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

/// An alias to `mio::tcp::TcpStream`.
#[derive(Debug)]
pub struct HttpStream(pub TcpStream);

impl Transport for HttpStream {
    fn take_socket_error(&mut self) -> io::Result<()> {
        self.0.take_socket_error()
    }
}

impl Read for HttpStream {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for HttpStream {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl Evented for HttpStream {
    #[inline]
    fn register(&self, selector: &mut Selector, token: Token, interest: EventSet, opts: PollOpt) -> io::Result<()> {
        self.0.register(selector, token, interest, opts)
    }

    #[inline]
    fn reregister(&self, selector: &mut Selector, token: Token, interest: EventSet, opts: PollOpt) -> io::Result<()> {
        self.0.reregister(selector, token, interest, opts)
    }

    #[inline]
    fn deregister(&self, selector: &mut Selector) -> io::Result<()> {
        self.0.deregister(selector)
    }
}

#[cfg(not(windows))]
impl ::vecio::Writev for HttpStream {
    #[inline]
    fn writev(&mut self, bufs: &[&[u8]]) -> io::Result<usize> {
        use ::vecio::Rawv;
        self.0.writev(bufs)
    }
}

/// An alias to `mio::tcp::TcpListener`.
#[derive(Debug)]
pub struct HttpListener(pub TcpListener);

impl HttpListener {
    /// Bind to a socket address.
    pub fn bind(addr: &SocketAddr) -> io::Result<HttpListener> {
        TcpListener::bind(addr)
            .map(HttpListener)
    }

    /// Try to duplicate the underlying listening socket.
    pub fn try_clone(&self) -> io::Result<HttpListener> {
        self.0.try_clone().map(HttpListener)
    }
}


impl Accept for HttpListener {
    type Output = HttpStream;

    #[inline]
    fn accept(&self) -> io::Result<Option<HttpStream>> {
        TryAccept::accept(&self.0).map(|ok| ok.map(HttpStream))
    }

    #[inline]
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
}

impl Evented for HttpListener {
    #[inline]
    fn register(&self, selector: &mut Selector, token: Token, interest: EventSet, opts: PollOpt) -> io::Result<()> {
        self.0.register(selector, token, interest, opts)
    }

    #[inline]
    fn reregister(&self, selector: &mut Selector, token: Token, interest: EventSet, opts: PollOpt) -> io::Result<()> {
        self.0.reregister(selector, token, interest, opts)
    }

    #[inline]
    fn deregister(&self, selector: &mut Selector) -> io::Result<()> {
        self.0.deregister(selector)
    }
}

impl IntoIterator for HttpListener {
    type Item = Self;
    type IntoIter = option::IntoIter<Self>;

    fn into_iter(self) -> Self::IntoIter {
        Some(self).into_iter()
    }
}

/// Deprecated
///
/// Use `SslClient` and `SslServer` instead.
pub trait Ssl {
    /// The protected stream.
    type Stream: Transport;
    /// Wrap a client stream with SSL.
    fn wrap_client(&self, stream: HttpStream, host: &str) -> ::Result<Self::Stream>;
    /// Wrap a server stream with SSL.
    fn wrap_server(&self, stream: HttpStream) -> ::Result<Self::Stream>;
}

/// An abstraction to allow any SSL implementation to be used with client-side `HttpsStream`s.
pub trait SslClient {
    /// The protected stream.
    type Stream: Transport;
    /// Wrap a client stream with SSL.
    fn wrap_client(&self, stream: HttpStream, host: &str) -> ::Result<Self::Stream>;
}

/// An abstraction to allow any SSL implementation to be used with server-side `HttpsStream`s.
pub trait SslServer {
    /// The protected stream.
    type Stream: Transport;
    /// Wrap a server stream with SSL.
    fn wrap_server(&self, stream: HttpStream) -> ::Result<Self::Stream>;
}

impl<S: Ssl> SslClient for S {
    type Stream = <S as Ssl>::Stream;

    fn wrap_client(&self, stream: HttpStream, host: &str) -> ::Result<Self::Stream> {
        Ssl::wrap_client(self, stream, host)
    }
}

impl<S: Ssl> SslServer for S {
    type Stream = <S as Ssl>::Stream;

    fn wrap_server(&self, stream: HttpStream) -> ::Result<Self::Stream> {
        Ssl::wrap_server(self, stream)
    }
}

/// A stream over the HTTP protocol, possibly protected by TLS.
#[derive(Debug)]
pub enum HttpsStream<S: Transport> {
    /// A plain text stream.
    Http(HttpStream),
    /// A stream protected by TLS.
    Https(S)
}

impl<S: Transport> Read for HttpsStream<S> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match *self {
            HttpsStream::Http(ref mut s) => s.read(buf),
            HttpsStream::Https(ref mut s) => s.read(buf)
        }
    }
}

impl<S: Transport> Write for HttpsStream<S> {
    #[inline]
    fn write(&mut self, msg: &[u8]) -> io::Result<usize> {
        match *self {
            HttpsStream::Http(ref mut s) => s.write(msg),
            HttpsStream::Https(ref mut s) => s.write(msg)
        }
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        match *self {
            HttpsStream::Http(ref mut s) => s.flush(),
            HttpsStream::Https(ref mut s) => s.flush()
        }
    }
}

#[cfg(not(windows))]
impl<S: Transport> ::vecio::Writev for HttpsStream<S> {
    #[inline]
    fn writev(&mut self, bufs: &[&[u8]]) -> io::Result<usize> {
        match *self {
            HttpsStream::Http(ref mut s) => s.writev(bufs),
            HttpsStream::Https(ref mut s) => s.writev(bufs)
        }
    }
}


#[cfg(unix)]
impl ::std::os::unix::io::AsRawFd for HttpStream {
    #[inline]
    fn as_raw_fd(&self) -> ::std::os::unix::io::RawFd {
        self.0.as_raw_fd()
    }
}

#[cfg(unix)]
impl<S: Transport + ::std::os::unix::io::AsRawFd> ::std::os::unix::io::AsRawFd for HttpsStream<S> {
    #[inline]
    fn as_raw_fd(&self) -> ::std::os::unix::io::RawFd {
        match *self {
            HttpsStream::Http(ref s) => s.as_raw_fd(),
            HttpsStream::Https(ref s) => s.as_raw_fd(),
        }
    }
}

impl<S: Transport> Evented for HttpsStream<S> {
    #[inline]
    fn register(&self, selector: &mut Selector, token: Token, interest: EventSet, opts: PollOpt) -> io::Result<()> {
        match *self {
            HttpsStream::Http(ref s) => s.register(selector, token, interest, opts),
            HttpsStream::Https(ref s) => s.register(selector, token, interest, opts),
        }
    }

    #[inline]
    fn reregister(&self, selector: &mut Selector, token: Token, interest: EventSet, opts: PollOpt) -> io::Result<()> {
        match *self {
            HttpsStream::Http(ref s) => s.reregister(selector, token, interest, opts),
            HttpsStream::Https(ref s) => s.reregister(selector, token, interest, opts),
        }
    }

    #[inline]
    fn deregister(&self, selector: &mut Selector) -> io::Result<()> {
        match *self {
            HttpsStream::Http(ref s) => s.deregister(selector),
            HttpsStream::Https(ref s) => s.deregister(selector),
        }
    }
}

impl<S: Transport> Transport for HttpsStream<S> {
    #[inline]
    fn take_socket_error(&mut self) -> io::Result<()> {
        match *self {
            HttpsStream::Http(ref mut s) => s.take_socket_error(),
            HttpsStream::Https(ref mut s) => s.take_socket_error(),
        }
    }

    #[inline]
    fn blocked(&self) -> Option<Blocked> {
        match *self {
            HttpsStream::Http(ref s) => s.blocked(),
            HttpsStream::Https(ref s) => s.blocked(),
        }
    }
}

/// An `HttpListener` over SSL.
#[derive(Debug)]
pub struct HttpsListener<S: SslServer> {
    listener: TcpListener,
    ssl: S,
}

impl<S: SslServer> HttpsListener<S> {
    /// Start listening to an address over HTTPS.
    #[inline]
    pub fn new(addr: &SocketAddr, ssl: S) -> io::Result<HttpsListener<S>> {
        TcpListener::bind(addr).map(|l| HttpsListener {
            listener: l,
            ssl: ssl
        })
    }

    /// Construct an `HttpsListener` from a bound `TcpListener`.
    pub fn with_listener(listener: TcpListener, ssl: S) -> HttpsListener<S> {
        HttpsListener {
            listener: listener,
            ssl: ssl
        }
    }
}

impl<S: SslServer> Accept for HttpsListener<S> {
    type Output = S::Stream;

    #[inline]
    fn accept(&self) -> io::Result<Option<S::Stream>> {
        self.listener.accept().and_then(|s| match s {
            Some((s, _)) => self.ssl.wrap_server(HttpStream(s)).map(Some).map_err(|e| {
                match e {
                    ::Error::Io(e) => e,
                    _ => io::Error::new(io::ErrorKind::Other, e),

                }
            }),
            None => Ok(None),
        })
    }

    #[inline]
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

impl<S: SslServer> Evented for HttpsListener<S> {
    #[inline]
    fn register(&self, selector: &mut Selector, token: Token, interest: EventSet, opts: PollOpt) -> io::Result<()> {
        self.listener.register(selector, token, interest, opts)
    }

    #[inline]
    fn reregister(&self, selector: &mut Selector, token: Token, interest: EventSet, opts: PollOpt) -> io::Result<()> {
        self.listener.reregister(selector, token, interest, opts)
    }

    #[inline]
    fn deregister(&self, selector: &mut Selector) -> io::Result<()> {
        self.listener.deregister(selector)
    }
}

impl<S: SslServer> IntoIterator for HttpsListener<S> {
    type Item = Self;
    type IntoIter = option::IntoIter<Self>;

    fn into_iter(self) -> Self::IntoIter {
        Some(self).into_iter()
    }
}

fn _assert_transport() {
    fn _assert<T: Transport>() {}
    _assert::<HttpsStream<HttpStream>>();
}

/*
#[cfg(all(not(feature = "openssl"), not(feature = "security-framework")))]
#[doc(hidden)]
pub type DefaultConnector = HttpConnector;

#[cfg(feature = "openssl")]
#[doc(hidden)]
pub type DefaultConnector = HttpsConnector<self::openssl::OpensslClient>;

#[cfg(all(feature = "security-framework", not(feature = "openssl")))]
pub type DefaultConnector = HttpsConnector<self::security_framework::ClientWrapper>;

#[doc(hidden)]
pub type DefaultTransport = <DefaultConnector as Connect>::Output;
*/

#[cfg(feature = "openssl")]
mod openssl {
    use std::io::{self, Write};
    use std::fmt;
    use std::path::Path;

    use rotor::mio::{Selector, Token, Evented, EventSet, PollOpt};

    use error::Error;
    use openssl::error::ErrorStack;
    use openssl::ssl::{ErrorCode, SslVerifyMode, Ssl, SslFiletype,
        SslContext, SslMethod, SslStream, SslMode, SslOptions, HandshakeError};

    use super::{HttpStream, Blocked};

    /// An implementation of `Ssl` for OpenSSL.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use hyper::Server;
    /// use hyper::net::Openssl;
    ///
    /// let ssl = Openssl::with_cert_and_key("/home/foo/cert", "/home/foo/key").unwrap();
    /// Server::https(&"0.0.0.0:443".parse().unwrap(), ssl).unwrap();
    /// ```
    ///
    /// For complete control, create a `SslContext` with the options you desire
    /// and then create `Openssl { context: ctx }
    #[derive(Debug, Clone)]
    pub struct Openssl {
        /// The `SslContext` from openssl crate.
        pub context: SslContext
    }

    /// A client-specific implementation of OpenSSL.
    #[derive(Debug, Clone)]
    pub struct OpensslClient(SslContext);

    impl Default for OpensslClient {
        fn default() -> OpensslClient {
            let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
            ctx.set_default_verify_paths().unwrap();
            ctx.set_options(
                SslOptions::NO_SSLV2 |
                SslOptions::NO_SSLV3 |
                SslOptions::NO_COMPRESSION
            );
            ctx.set_mode(SslMode::ENABLE_PARTIAL_WRITE);

            // cipher list taken from curl:
            // https://github.com/curl/curl/blob/5bf5f6ebfcede78ef7c2b16daa41c4b7ba266087/lib/vtls/openssl.h#L120
            ctx.set_cipher_list("ALL!EXPORT!EXPORT40!EXPORT56!aNULL!LOW!RC4@STRENGTH").unwrap();
            OpensslClient::new(ctx.build())
        }
    }

    impl OpensslClient {
        /// Creates a new OpensslClient with a custom SslContext
        pub fn new(ctx: SslContext) -> OpensslClient {
            OpensslClient(ctx)
        }
    }

    impl super::SslClient for OpensslClient {
        type Stream = OpensslStream<HttpStream>;

        #[cfg(not(windows))]
        fn wrap_client(&self, stream: HttpStream, host: &str) -> ::Result<Self::Stream> {
            let mut ssl = try!(Ssl::new(&self.0));
            try!(ssl.set_hostname(host));
            let host = host.to_owned();
            ssl.set_verify_callback(SslVerifyMode::PEER, move |p, x| ::openssl_verify::verify_callback(&host, p, x));
            ssl.connect(stream)
                .map(openssl_stream)
                .map_err(From::from)
        }


        #[cfg(windows)]
        fn wrap_client(&self, stream: HttpStream, host: &str) -> ::Result<Self::Stream> {
            let mut ssl = try!(Ssl::new(&self.0));
            try!(ssl.set_hostname(host));
            ssl.connect(stream)
                .map(openssl_stream)
                .map_err(From::from)
        }
    }

    impl Default for Openssl {
        fn default() -> Openssl {
            Openssl {
                context: SslContext::builder(SslMethod::tls()).unwrap_or_else(|e| {
                    // if we cannot create a SslContext, that's because of a
                    // serious problem. just crash.
                    panic!("{}", e)
                }).build()
            }
        }
    }

    impl Openssl {
        /// Ease creating an `Openssl` with a certificate and key.
        pub fn with_cert_and_key<C, K>(cert: C, key: K) -> Result<Openssl, ErrorStack>
        where C: AsRef<Path>, K: AsRef<Path> {
            let mut ctx = try!(SslContext::builder(SslMethod::tls()));
            try!(ctx.set_cipher_list("ALL!EXPORT!EXPORT40!EXPORT56!aNULL!LOW!RC4@STRENGTH"));
            try!(ctx.set_certificate_file(cert.as_ref(), SslFiletype::PEM));
            try!(ctx.set_private_key_file(key.as_ref(), SslFiletype::PEM));
            Ok(Openssl { context: ctx.build() })
        }
    }

    impl super::Ssl for Openssl {
        type Stream = OpensslStream<HttpStream>;

        fn wrap_client(&self, stream: HttpStream, host: &str) -> ::Result<Self::Stream> {
            let mut ssl = try!(Ssl::new(&self.context));
            try!(ssl.set_hostname(host));
            match ssl.connect(stream) {
                Ok(stream) => Ok(openssl_stream(stream)),
                Err(HandshakeError::WouldBlock(stream)) => Ok(mid_openssl_stream(stream)),
                Err(err) => Err(From::from(err)),
            }
        }

        fn wrap_server(&self, stream: HttpStream) -> ::Result<Self::Stream> {
            let ssl = try!(Ssl::new(&self.context));
            match ssl.accept(stream) {
                Ok(ssl_stream) => Ok(openssl_stream(ssl_stream)),
                Err(e) => Err(e.into())
            }
        }
    }


    use ::openssl::ssl::MidHandshakeSslStream;

    #[derive(Debug)]
    enum OpensslStreamInner<T> {
        Connected(SslStream<T>),
        Connecting(MidHandshakeSslStream<T>),
    }

    /// A transport protected by OpenSSL.
    #[derive(Debug)]
    pub struct OpensslStream<T> {
        inner: Option<OpensslStreamInner<T>>,
        blocked: Option<Blocked>,
    }

    fn mid_openssl_stream<T>(stream: MidHandshakeSslStream<T>) -> OpensslStream<T> {
        OpensslStream {
            inner: Some(OpensslStreamInner::Connecting(stream)),
            blocked: None,
        }
    }

    fn openssl_stream<T>(stream: SslStream<T>) -> OpensslStream<T> {
        OpensslStream {
            inner: Some(OpensslStreamInner::Connected(stream)),
            blocked: None,
        }
    }

    impl<T: super::Transport> OpensslStream<T> {
        fn inner_stream_ref(&self) -> &T {
            match *self.inner.as_ref().expect("Inner exists!") {
                OpensslStreamInner::Connecting(ref stream) => stream.get_ref(),
                OpensslStreamInner::Connected(ref stream) => stream.get_ref(),
            }
        }

        fn inner_stream_mut(&mut self) -> &mut T {
            match *self.inner.as_mut().expect("Inner exists!") {
                OpensslStreamInner::Connecting(ref mut stream) => stream.get_mut(),
                OpensslStreamInner::Connected(ref mut stream) => stream.get_mut(),
            }
        }
    }

    fn handshake<S>(
        op: &str,
        stream: MidHandshakeSslStream<S>,
        inner: &mut Option<OpensslStreamInner<S>>,
        blocked: &mut Option<Blocked>
    ) -> io::Result<usize> {
        match stream.handshake() {
            Ok(stream) => {
                debug!("{} - Resolved handshake, connected stream", op);
                *inner = Some(OpensslStreamInner::Connected(stream));
                Err(io::Error::new(io::ErrorKind::WouldBlock, Error::SslHandshake))
            },
            Err(HandshakeError::WouldBlock(stream)) => {
                debug!("{} - Handshake would block", op);
                let code = stream.error().code();
                *inner = Some(OpensslStreamInner::Connecting(stream));

                match code {
                    ErrorCode::WANT_WRITE => *blocked = Some(Blocked::Write),
                    ErrorCode::WANT_READ => *blocked = Some(Blocked::Read),
                    _ => unreachable!(),
                }

                Err(io::Error::new(io::ErrorKind::WouldBlock, Error::SslHandshake))
            },
            Err(HandshakeError::SetupFailure(e)) => {
                Err(io::Error::new(io::ErrorKind::Other, Error::SslStack(e)))
            },
            Err(HandshakeError::Failure(f)) => {
                Err(io::Error::new(io::ErrorKind::Other, Error::Ssl(f.into_error())))
            },
        }
    }

    impl<T: super::Transport + fmt::Debug> io::Read for OpensslStream<T> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.blocked = None;

            match self.inner.take().expect("Inner exists") {
                OpensslStreamInner::Connecting(stream) => {
                    handshake("read", stream, &mut self.inner, &mut self.blocked)
                },
                OpensslStreamInner::Connected(mut stream) => {
                    let result = stream.ssl_read(buf);
                    self.inner = Some(OpensslStreamInner::Connected(stream));
                    result.or_else(|e| match e.code() {
                        ErrorCode::ZERO_RETURN => Ok(0),
                        ErrorCode::WANT_WRITE => {
                            self.blocked = Some(Blocked::Write);
                            Err(io::Error::new(io::ErrorKind::WouldBlock, Error::Ssl(e)))
                        },
                        ErrorCode::WANT_READ => {
                            self.blocked = Some(Blocked::Read);
                            Err(io::Error::new(io::ErrorKind::WouldBlock, Error::Ssl(e)))
                        },
                        _ => Err(io::Error::new(io::ErrorKind::Other, Error::Ssl(e))),
                    })
                }
            }
        }
    }

    impl<T: super::Transport + fmt::Debug> io::Write for OpensslStream<T> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.blocked = None;

            match self.inner.take().expect("Inner exists") {
                OpensslStreamInner::Connecting(stream) => {
                    handshake("write", stream, &mut self.inner, &mut self.blocked)
                },
                OpensslStreamInner::Connected(mut stream) => {
                    let result = stream.ssl_write(buf);
                    self.inner = Some(OpensslStreamInner::Connected(stream));
                    result.or_else(|e| match e.code() {
                        ErrorCode::ZERO_RETURN => Ok(0),
                        ErrorCode::WANT_READ => {
                            self.blocked = Some(Blocked::Read);
                            Err(io::Error::new(io::ErrorKind::WouldBlock, Error::Ssl(e)))
                        },
                        ErrorCode::WANT_WRITE => {
                            self.blocked = Some(Blocked::Write);
                            Err(io::Error::new(io::ErrorKind::WouldBlock, Error::Ssl(e)))
                        },
                        _ => Err(io::Error::new(io::ErrorKind::Other, Error::Ssl(e))),
                    })
                }
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            self.inner_stream_mut().flush()
        }
    }

    impl<T: super::Transport> Evented for OpensslStream<T> {
        #[inline]
        fn register(&self, selector: &mut Selector, token: Token, interest: EventSet, opts: PollOpt) -> io::Result<()> {
            self.inner_stream_ref().register(selector, token, interest, opts)
        }

        #[inline]
        fn reregister(&self, selector: &mut Selector, token: Token, interest: EventSet, opts: PollOpt) -> io::Result<()> {
            self.inner_stream_ref().reregister(selector, token, interest, opts)
        }

        #[inline]
        fn deregister(&self, selector: &mut Selector) -> io::Result<()> {
            self.inner_stream_ref().deregister(selector)
        }
    }

    impl<T: super::Transport + fmt::Debug> ::vecio::Writev for OpensslStream<T> {
        fn writev(&mut self, bufs: &[&[u8]]) -> io::Result<usize> {
            let vec = bufs.concat();
            self.write(&vec)
        }
    }

    impl<T: super::Transport + fmt::Debug> super::Transport for OpensslStream<T> {
        fn take_socket_error(&mut self) -> io::Result<()> {
            self.inner_stream_mut().take_socket_error()
        }

        fn blocked(&self) -> Option<super::Blocked> {
            self.blocked
        }
    }
}


#[cfg(feature = "security-framework")]
mod security_framework {
    use std::io::{self, Read, Write};

    use error::Error;
    use net::{SslClient, SslServer, HttpStream, Transport, Blocked};

    use security_framework::secure_transport::SslStream;
    pub use security_framework::secure_transport::{ClientBuilder as SecureTransportClient, ServerBuilder as SecureTransportServer};
    use rotor::mio::{Selector, Token, Evented, EventSet, PollOpt};

    impl SslClient for SecureTransportClient {
        type Stream = SecureTransport<HttpStream>;

        fn wrap_client(&self, stream: HttpStream, host: &str) -> ::Result<Self::Stream> {
            match self.handshake(host, journal(stream)) {
                Ok(s) => Ok(SecureTransport(s)),
                Err(e) => Err(Error::Ssl(e.into())),
            }
        }
    }

    impl SslServer for SecureTransportServer {
        type Stream = SecureTransport<HttpStream>;

        fn wrap_server(&self, stream: HttpStream) -> ::Result<Self::Stream> {
            match self.handshake(journal(stream)) {
                Ok(s) => Ok(SecureTransport(s)),
                Err(e) => Err(Error::Ssl(e.into())),
            }
        }
    }

    /// A transport protected by Security Framework.
    #[derive(Debug)]
    pub struct SecureTransport<T>(SslStream<Journal<T>>);

    impl<T: Transport> io::Read for SecureTransport<T> {
        #[inline]
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl<T: Transport> io::Write for SecureTransport<T> {
        #[inline]
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }

        #[inline]
        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }


    impl<T: Transport> Evented for SecureTransport<T> {
        #[inline]
        fn register(&self, selector: &mut Selector, token: Token, interest: EventSet, opts: PollOpt) -> io::Result<()> {
            self.0.get_ref().inner.register(selector, token, interest, opts)
        }

        #[inline]
        fn reregister(&self, selector: &mut Selector, token: Token, interest: EventSet, opts: PollOpt) -> io::Result<()> {
            self.0.get_ref().inner.reregister(selector, token, interest, opts)
        }

        #[inline]
        fn deregister(&self, selector: &mut Selector) -> io::Result<()> {
            self.0.get_ref().inner.deregister(selector)
        }
    }

    impl<T: Transport> ::vecio::Writev for SecureTransport<T> {
        fn writev(&mut self, bufs: &[&[u8]]) -> io::Result<usize> {
            let vec = bufs.concat();
            self.write(&vec)
        }
    }

    impl<T: Transport> Transport for SecureTransport<T> {
        fn take_socket_error(&mut self) -> io::Result<()> {
            self.0.get_mut().inner.take_socket_error()
        }

        fn blocked(&self) -> Option<super::Blocked> {
            self.0.get_ref().blocked
        }
    }


    // Records if this object was blocked on reading or writing.
    #[derive(Debug)]
    struct Journal<T> {
        inner: T,
        blocked: Option<Blocked>,
    }

    fn journal<T: Read + Write>(inner: T) -> Journal<T> {
        Journal {
            inner: inner,
            blocked: None,
        }
    }

    impl<T: Read> Read for Journal<T> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.blocked = None;
            self.inner.read(buf).map_err(|e| match e.kind() {
                io::ErrorKind::WouldBlock => {
                    self.blocked = Some(Blocked::Read);
                    e
                },
                _ => e
            })
        }
    }

    impl<T: Write> Write for Journal<T> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.blocked = None;
            self.inner.write(buf).map_err(|e| match e.kind() {
                io::ErrorKind::WouldBlock => {
                    self.blocked = Some(Blocked::Write);
                    e
                },
                _ => e
            })
        }

        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }

}
