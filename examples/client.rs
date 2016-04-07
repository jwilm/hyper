#![deny(warnings)]
extern crate hyper;

extern crate env_logger;

use std::env;
use std::io;
use std::sync::mpsc;

use hyper::client::{Client, Request, Response};
use hyper::header::Connection;
use hyper::{Decoder, Encoder, Next};
use hyper::net::DefaultTransport as HttpStream;

enum Message {
    Response(Response, Vec<u8> /* body */),
    Error(String),
}

struct BufferingHandler {
    tx: mpsc::Sender<Message>,
    buf: Vec<u8>,
    response: Option<Response>,
}

impl BufferingHandler {
    pub fn new(tx: mpsc::Sender<Message>) -> Self {
        BufferAndSend {
            tx: tx,
            buf: Vec::new(),
            response: None,
        }
    }
}

impl hyper::client::Handler<HttpStream> for BufferingHandler {
    fn on_request(&mut self, req: &mut Request) -> Next {
        req.headers_mut().set(Connection::close());
        Next::read()
    }

    fn on_request_writable(&mut self, _encoder: &mut Encoder<HttpStream>) -> Next {
        Next::read()
    }

    fn on_response(&mut self, res: Response) -> Next {
        self.response = Some(res);
        Next::read()
    }

    fn on_response_readable(&mut self, decoder: &mut Decoder<HttpStream>) -> Next {
        match io::copy(decoder, &mut self.buf) {
            Ok(0) => {
                let mut buf = Vec::new();
                ::std::mem::swap(&mut self.buf, &mut buf);
                let resp = self.response.take().expect("Response received and not consumed");
                self.tx.send(Message::Response(resp, buf)).ok();
                Next::end()
            },
            Ok(_) => Next::read(),
            Err(e) => match e.kind() {
                io::ErrorKind::WouldBlock => Next::read(),
                _ => {
                    self.tx.send(Message::Error(format!("ERROR: {}", e))).ok();
                    Next::end()
                }
            }
        }
    }

    fn on_error(&mut self, err: hyper::Error) -> Next {
        println!("ERROR: {}", err);
        Next::remove()
    }
}

fn main() {
    env_logger::init().unwrap();

    let url = match env::args().nth(1) {
        Some(url) => url,
        None => {
            println!("Usage: client <url>");
            return;
        }
    };

    let (tx, rx) = mpsc::channel();
    let client = Client::new().expect("Failed to create a Client");
    let to_send = 200;

    for _ in 0..to_send {
        client.request(url.parse().unwrap(), BufferingHandler::new(tx.clone())).unwrap();
    }

    let sent = to_send;

    let mut i = 0;
    let mut received = 0;
    loop {
        if let Ok(msg) = rx.try_recv() {
            match msg {
                Message::Error(err) => println!("{}", err),
                Message::Response(_resp, body) => {
                    let mut cursor = io::Cursor::new(body);
                    io::copy(&mut cursor, &mut io::stdout()).ok();
                }
            }
            received += 1;
            i = 0;
            if received == sent {
                break;
            }
        } else {
            ::std::thread::sleep(::std::time::Duration::from_millis(50));
            i += 1;
            if i > 100 {
                println!("timed out while waiting for responses");
                println!("got {} / {}", received, sent);
                ::std::process::exit(1);
            }
        }
    }
    client.close();
}
