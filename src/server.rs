use crate::utils::*;
use log::{error, info};
use std::{
    convert::TryInto,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs},
    ops::{Deref, DerefMut},
    sync::Arc,
};
use std::collections::HashMap;
use thiserror::Error;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

type Result<T> = std::result::Result<T, Socks5ServerError>;

#[derive(Debug, Error)]
pub enum Socks5ServerError {
    #[error("unrecognized protocol")]
    UnknowProtocol,
    #[error("unsupport authenticate method")]
    UnsupportAuth,
    #[error("unsupport socks5 command {0:#04X}")]
    UnsupportCommand(u8),
    #[error("unknow destination type {0:#04X}")]
    UnknowAddrType(u8),
    #[error("invalid hostname received")]
    InvalidHost(#[from] std::str::Utf8Error),
    #[error("DNS lookup error: {0}")]
    DNSError(String),
    #[error(transparent)]
    IOError(#[from] io::Error),
}

#[derive(Debug, Clone)]
pub struct Client {
    pub password: String,
    pub gateway: SocketAddr
}

pub type Clients = HashMap<String, Client>;

pub struct Socks5Server {
    conn: TcpSocket,
    clients: Arc<Clients>
}

pub fn new(addr: SocketAddr, clients: Arc<Clients>) -> Result<Socks5Server> {
    let conn = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    conn.bind(addr)?;

    Ok(Socks5Server { conn, clients })
}

impl Socks5Server {
    pub async fn run(self) -> Result<()> {
        info!("Starting on {}", self.conn.local_addr()?);
        let conn = self.conn.listen(1024)?;
        loop {
            let (conn, source) = conn.accept().await?;
            println!("Accepted connection from {}", source);
            let cs = self.clients.clone();
            tokio::spawn(async move {
                let result = handle_client(conn, cs).await;
                if let Err(e) = result {
                    error!("{:?}, source {}", e, source);
                    println!("{:?}, source {}", e, source);
                }
            });
        }
    }
}

impl_deref!(PendingHandshake, TcpStream);
impl PendingHandshake {
    async fn handshake(mut self) -> Result<PendingAuthenticate> {
        let mut header = [0u8; 2];
        self.read_exact(&mut header).await?;
        if header[0] != SOCKS_VER {
            return Err(Socks5ServerError::UnknowProtocol);
        }
        let mut matched = false;
        for _ in 0..header[1] {
            let mut m = [0u8; 1];
            self.read_exact(&mut m).await?;
            matched = 0x02 == m[0]; // check for auth_method ~ user_pass
        }
        if !matched {
            return Err(Socks5ServerError::UnsupportAuth);
        }

        self.write_all(&[SOCKS_VER, 0x02]).await?;
        self.flush().await?;

        Ok(PendingAuthenticate(self.0))
    }
}

impl_deref!(PendingAuthenticate, TcpStream);
impl PendingAuthenticate {
    async fn authenticate(mut self, clients: &Arc<Clients>) -> Result<PendingCommand> {
        let mut header = [0u8; 2];
        self.read_exact(&mut header).await?;

        let name_lenth = header[1];
        let pass_lenth;
        let mut one_byte = [0u8; 1];
        let mut name_vec: Vec<u8> = Vec::new();
        let mut pass_vec: Vec<u8> = Vec::new();

        for _i in 0..name_lenth {
            self.read_exact(&mut one_byte).await?;
            name_vec.push(one_byte[0]);
        }

        self.read_exact(&mut one_byte).await?;
        pass_lenth = one_byte[0];

        for _i in 0..pass_lenth {
            self.read_exact(&mut one_byte).await?;
            pass_vec.push(one_byte[0]);
        }

        let user_name = String::from_utf8_lossy(&name_vec).to_string();
        let user_pwd = String::from_utf8_lossy(&pass_vec).to_string();


        match clients.as_ref().get(&user_name) {
            None => {
                self.write_all(&[SOCKS_AUTH_VER, SocksError::FAIL as u8]).await?;
                self.flush().await?;
                Err(Socks5ServerError::UnsupportAuth)
            }
            Some(Client { password, .. }) if *password != user_pwd => {
                self.write_all(&[SOCKS_AUTH_VER, SocksError::FAIL as u8]).await?;
                self.flush().await?;
                Err(Socks5ServerError::UnsupportAuth)
            },
            Some(Client { gateway, .. }) => {
                //Authentication succeeded
                self.write_all(&[SOCKS_AUTH_VER, SocksError::SUCCESS as u8]).await?;
                self.flush().await?;
                Ok(PendingCommand { conn: self.0, gateway: gateway.clone() })
            }
        }
    }
}

struct PendingCommand {
    conn: TcpStream,
    gateway: SocketAddr
}

impl PendingCommand {
    async fn handle_command(&mut self) -> Result<SocketAddr> {
        let mut header = [0u8; 4];
        self.conn.read_exact(&mut header).await?;
        if header[0] != SOCKS_VER || header[2] != SOCKS_RSV {
            return Err(Socks5ServerError::UnknowProtocol);
        } else if header[1] != SOCKS_COMMAND_CONNECT {
            return Err(Socks5ServerError::UnsupportCommand(header[1]));
        }

        match header[3] {
            SOCKS_ADDR_IPV4 => {
                let mut buffer = [0u8; 4 + 2];
                self.conn.read_exact(&mut buffer).await?;
                let ip: [u8; 4] = buffer[..4].try_into().unwrap();
                let ip: Ipv4Addr = Ipv4Addr::from(ip);
                let port = u16::from_be_bytes([buffer[4], buffer[5]]);
                let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
                info!("connecting to {}", addr);
                Ok(addr)
            }
            SOCKS_ADDR_IPV6 => {
                let mut buffer = [0u8; 16 + 2];
                self.conn.read_exact(&mut buffer).await?;
                let ip: [u8; 16] = buffer[..16].try_into().unwrap();
                let ip = Ipv6Addr::from(ip);
                let port = u16::from_be_bytes([buffer[16], buffer[17]]);
                let addr = SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0));
                info!("connecting to {}", addr);
                Ok(addr)
            }
            SOCKS_ADDR_DOMAINNAME => {
                let mut buffer = [0u8; 255];
                self.conn.read_exact(&mut buffer[..1]).await?;
                let len = buffer[0];
                self.conn.read_exact(&mut buffer[..len as usize]).await?;
                let mut port = [0u8; 2];
                self.conn.read_exact(&mut port).await?;
                let port = u16::from_be_bytes(port);
                let host = std::str::from_utf8(&buffer[..len as usize])?;
                let sock = (host, port).to_socket_addrs()?.next();
                if let None = sock {
                    return Err(Socks5ServerError::DNSError(host.into()));
                }
                let addr = sock.unwrap();
                info!("connecting to {}:{}", host, port);
                Ok(addr)
            }
            _ => Err(Socks5ServerError::UnknowAddrType(header[3])),
        }
    }
    async fn reply(mut self, content: &[u8]) -> Result<TcpStream> {
        self.conn.write_all(&content).await?;
        self.conn.flush().await?;
        Ok(self.conn)
    }
}
async fn handle_client(conn: TcpStream, cs: Arc<Clients>) -> Result<()> {
    let mut conn = PendingHandshake(conn)
        .handshake()
        .await?
        .authenticate(&cs)
        .await?;
    let addr = conn.handle_command().await;
    let mut rep = [
        SOCKS_VER,
        SocksError::SUCCESS as u8,
        SOCKS_RSV,
        SOCKS_ADDR_IPV4,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    let addr = match addr {
        Ok(c) => c,
        Err(e) => {
            rep[1] = match e {
                Socks5ServerError::DNSError(_) => SocksError::HOST,
                Socks5ServerError::UnsupportCommand(_) => SocksError::COMMAND,
                Socks5ServerError::UnknowAddrType(_) => SocksError::ADDRESS,
                _ => SocksError::FAIL,
            } as u8;
            conn.reply(&rep).await?;
            return Err(e);
        }
    };

    // --------------------------------
    let sc = TcpSocket::new_v4()?;
    sc.bind(conn.gateway)?;
    let delegate = sc.connect(addr).await;
    let delegate = match delegate {
        Ok(c) => c,
        Err(e) => {
            rep[1] = SocksError::NETWORK as u8;
            conn.reply(&rep).await?;
            return Err(e.into());
        }
    };

    let conn = conn.reply(&rep).await?;

    let (conn_r, conn_w) = conn.into_split();
    let (delegate_r, delegate_w) = delegate.into_split();

    tokio::spawn(async move {
        copy(conn_r, delegate_w).await;
    });

    tokio::spawn(async move {
        copy(delegate_r, conn_w).await;
    });

    Ok(())
}

async fn copy(mut r: impl AsyncRead + Unpin, mut w: impl AsyncWrite + Unpin) {
    tokio::io::copy(&mut r, &mut w).await.unwrap_or(0);

    w.shutdown().await.unwrap_or(());
}
