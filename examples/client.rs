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


struct Dump(mpsc::Sender<()>);

impl Drop for Dump {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

impl hyper::client::Handler<HttpStream> for Dump {
    fn on_request(&mut self, req: &mut Request) -> Next {
        req.headers_mut().set(Connection::close());
        Next::read()
    }

    fn on_request_writable(&mut self, _encoder: &mut Encoder<HttpStream>) -> Next {
        Next::read()
    }

    fn on_response(&mut self, _res: Response) -> Next {
        Next::read()
    }

    fn on_response_readable(&mut self, decoder: &mut Decoder<HttpStream>) -> Next {
        match io::copy(decoder, &mut io::stdout()) {
            Ok(0) => Next::end(),
            Ok(_) => Next::read(),
            Err(e) => match e.kind() {
                io::ErrorKind::WouldBlock => Next::read(),
                _ => {
                    println!("ERROR: {}", e);
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
    let to_send = 20000;

    for _ in 0..to_send {
        client.request(url.parse().unwrap(), Dump(tx.clone())).unwrap();
    }

    let sent = to_send;

    let mut i =-0;
    let mut received = 0;
    loop {
        if let Ok(_) = rx.try_recv() {
            received += 1;
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
