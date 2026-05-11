use byteorder::{BigEndian, ByteOrder};
use ssh_encoding::{Decode, Encode, Reader};

use crate::msg;

use crate::map_err;

pub(crate) const MAX_NAME_LIST_BYTES: usize = 16 * 1024;
pub(crate) const MAX_NAME_LIST_ENTRIES: usize = 1024;

pub(crate) fn ensure_end(reader: &impl Reader) -> Result<(), crate::Error> {
    if reader.is_finished() {
        Ok(())
    } else {
        Err(ssh_encoding::Error::TrailingData {
            remaining: reader.remaining_len(),
        }
        .into())
    }
}

pub(crate) fn take_u8(input: &mut &[u8]) -> Result<u8, crate::Error> {
    let (&value, rest) = input.split_first().ok_or(ssh_encoding::Error::Length)?;
    *input = rest;
    Ok(value)
}

pub(crate) fn take_u32(input: &mut &[u8]) -> Result<u32, crate::Error> {
    let (bytes, rest) = input
        .split_at_checked(4)
        .ok_or(ssh_encoding::Error::Length)?;
    *input = rest;
    Ok(BigEndian::read_u32(bytes))
}

pub(crate) fn take_bytes<'a>(
    input: &mut &'a [u8],
    max_len: usize,
) -> Result<&'a [u8], crate::Error> {
    let len = take_u32(input)? as usize;
    if len > max_len {
        return Err(crate::Error::PacketSize(len));
    }
    let (value, rest) = input
        .split_at_checked(len)
        .ok_or(ssh_encoding::Error::Length)?;
    *input = rest;
    Ok(value)
}

pub(crate) fn take_str<'a>(
    input: &mut &'a [u8],
    max_len: usize,
) -> Result<&'a str, crate::Error> {
    Ok(std::str::from_utf8(take_bytes(input, max_len)?)?)
}

pub(crate) fn take_name_list<'a>(input: &mut &'a [u8]) -> Result<Vec<&'a str>, crate::Error> {
    let value = take_str(input, MAX_NAME_LIST_BYTES)?;
    if value.is_empty() {
        return Ok(Vec::new());
    }

    let mut names = Vec::new();
    for name in value.split(',') {
        if name.is_empty() {
            return Err(crate::Error::Inconsistent);
        }
        if names.len() == MAX_NAME_LIST_ENTRIES {
            return Err(crate::Error::PacketSize(names.len() + 1));
        }
        names.push(name);
    }
    Ok(names)
}

#[derive(Debug)]
pub struct OpenChannelMessage {
    pub typ: ChannelType,
    pub recipient_channel: u32,
    pub recipient_window_size: u32,
    pub recipient_maximum_packet_size: u32,
}

impl OpenChannelMessage {
    pub fn parse<R: Reader>(r: &mut R) -> Result<Self, crate::Error> {
        // https://tools.ietf.org/html/rfc4254#section-5.1
        let typ = map_err!(String::decode(r))?;
        let sender = map_err!(u32::decode(r))?;
        let window = map_err!(u32::decode(r))?;
        let maxpacket = map_err!(u32::decode(r))?;
        validate_remote_channel_packet_size(maxpacket)?;

        let typ = match typ.as_str() {
            "session" => ChannelType::Session,
            "x11" => {
                let originator_address = map_err!(String::decode(r))?;
                let originator_port = map_err!(u32::decode(r))?;
                ChannelType::X11 {
                    originator_address,
                    originator_port,
                }
            }
            "direct-tcpip" => ChannelType::DirectTcpip(TcpChannelInfo::decode(r)?),
            "direct-streamlocal@openssh.com" => {
                ChannelType::DirectStreamLocal(StreamLocalChannelInfo::decode(r)?)
            }
            "forwarded-tcpip" => ChannelType::ForwardedTcpIp(TcpChannelInfo::decode(r)?),
            "forwarded-streamlocal@openssh.com" => {
                ChannelType::ForwardedStreamLocal(StreamLocalChannelInfo::decode(r)?)
            }
            "auth-agent@openssh.com" => ChannelType::AgentForward,
            _ => ChannelType::Unknown { typ },
        };

        Ok(Self {
            typ,
            recipient_channel: sender,
            recipient_window_size: window,
            recipient_maximum_packet_size: maxpacket,
        })
    }

    /// Pushes a confirmation that this channel was opened to the vec.
    pub fn confirm(
        &self,
        buffer: &mut Vec<u8>,
        sender_channel: u32,
        window_size: u32,
        packet_size: u32,
    ) -> Result<(), crate::Error> {
        push_packet!(buffer, {
            msg::CHANNEL_OPEN_CONFIRMATION.encode(buffer)?;
            self.recipient_channel.encode(buffer)?; // remote channel number.
            sender_channel.encode(buffer)?; // our channel number.
            window_size.encode(buffer)?;
            packet_size.encode(buffer)?;
        });
        Ok(())
    }

    /// Pushes a failure message to the vec.
    pub fn fail(
        &self,
        buffer: &mut Vec<u8>,
        reason: u8,
        message: &[u8],
    ) -> Result<(), crate::Error> {
        push_packet!(buffer, {
            msg::CHANNEL_OPEN_FAILURE.encode(buffer)?;
            self.recipient_channel.encode(buffer)?;
            (reason as u32).encode(buffer)?;
            message.encode(buffer)?;
            "en".encode(buffer)?;
        });
        Ok(())
    }

    /// Pushes an unknown type error to the vec.
    pub fn unknown_type(&self, buffer: &mut Vec<u8>) -> Result<(), crate::Error> {
        self.fail(
            buffer,
            msg::SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
            b"Unknown channel type",
        )
    }
}

pub(crate) fn validate_remote_channel_packet_size(maxpacket: u32) -> Result<(), crate::Error> {
    if maxpacket == 0 || maxpacket as usize > crate::cipher::MAXIMUM_PACKET_LEN {
        Err(crate::Error::PacketSize(maxpacket as usize))
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub enum ChannelType {
    Session,
    X11 {
        originator_address: String,
        originator_port: u32,
    },
    DirectTcpip(TcpChannelInfo),
    DirectStreamLocal(StreamLocalChannelInfo),
    ForwardedTcpIp(TcpChannelInfo),
    ForwardedStreamLocal(StreamLocalChannelInfo),
    AgentForward,
    Unknown {
        typ: String,
    },
}

#[derive(Debug)]
pub struct TcpChannelInfo {
    pub host_to_connect: String,
    pub port_to_connect: u32,
    pub originator_address: String,
    pub originator_port: u32,
}

#[derive(Debug)]
pub struct StreamLocalChannelInfo {
    pub socket_path: String,
}

impl Decode for StreamLocalChannelInfo {
    type Error = ssh_encoding::Error;

    fn decode(r: &mut impl Reader) -> Result<Self, Self::Error> {
        let socket_path = String::decode(r)?.to_owned();
        Ok(Self { socket_path })
    }
}

impl Decode for TcpChannelInfo {
    type Error = ssh_encoding::Error;

    fn decode(r: &mut impl Reader) -> Result<Self, Self::Error> {
        let host_to_connect = String::decode(r)?;
        let port_to_connect = u32::decode(r)?;
        let originator_address = String::decode(r)?;
        let originator_port = u32::decode(r)?;

        Ok(Self {
            host_to_connect,
            port_to_connect,
            originator_address,
            originator_port,
        })
    }
}

#[derive(Debug)]
pub(crate) struct ChannelOpenConfirmation {
    pub recipient_channel: u32,
    pub sender_channel: u32,
    pub initial_window_size: u32,
    pub maximum_packet_size: u32,
}

impl Decode for ChannelOpenConfirmation {
    type Error = ssh_encoding::Error;

    fn decode(r: &mut impl Reader) -> Result<Self, Self::Error> {
        let recipient_channel = u32::decode(r)?;
        let sender_channel = u32::decode(r)?;
        let initial_window_size = u32::decode(r)?;
        let maximum_packet_size = u32::decode(r)?;

        Ok(Self {
            recipient_channel,
            sender_channel,
            initial_window_size,
            maximum_packet_size,
        })
    }
}
