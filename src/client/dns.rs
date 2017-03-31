use std::io;
use std::net::IpAddr;
use std::vec;

use c_ares_experiment;

use http::channel;

pub struct Dns {
    rx: channel::Receiver<Answer>,
    c_ares: c_ares_experiment::Dns,
}

pub type Answer = (String, io::Result<IpAddrs>);

pub struct IpAddrs {
    iter: vec::IntoIter<IpAddr>,
}

impl Iterator for IpAddrs {
    type Item = IpAddr;
    #[inline]
    fn next(&mut self) -> Option<IpAddr> {
        self.iter.next()
    }
}

impl Dns {
    pub fn new(notify: (channel::Sender<Answer>, channel::Receiver<Answer>), _threads: usize) -> Dns {
        let (tx, rx) = notify;

        Dns {
            rx: rx,
            c_ares: c_ares_experiment::Dns::new(move |res| {
                let (host, res) = res;
                let res = res.map(|v| IpAddrs { iter: v.into_iter() });
                let _ = tx.send((host.into_owned(), res));
            })
        }
    }

    pub fn resolve<T: Into<String>>(&self, hostname: T) {
        let hostname = hostname.into();
        self.c_ares.resolve(hostname.clone())
            .expect("DNS worker died unexpectedly");
    }

    pub fn resolved(&self) -> Result<Answer, channel::TryRecvError> {
        self.rx.try_recv()
    }
}
