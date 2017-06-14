/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#[macro_use]
extern crate t2plugin;
extern crate libc;
#[macro_use]
extern crate lazy_static;

use std::str;
use std::collections::HashSet;

use t2plugin::{T2Plugin, Header, BinaryType, output_string, output_num};
use t2plugin::nethdr::{Packet, Flow, L4Type};
use t2plugin::slread::{SliceReader, TrimBytes};


//  ------------  Plugin per flow structure  ------------

struct RustExample {
    // variable to compute the network throughput
    byte_count: u64,

    // list of extracted PHPSESSID cookies
    php_ids: HashSet<(bool, String)>,

    // variables related to SSL/TLS
    tls_sni: String,
}


//  ------------  Supported TLS versions enum  ------------

#[derive(PartialEq)]
enum TlsVersion {
    UNKNOWN,
    SSLv3,
    TLSv1,
    TLSv11,
    TLSv12,
}

impl TlsVersion {
    fn from_u16(val: u16) -> TlsVersion {
        match val {
            0x0300 => TlsVersion::SSLv3,
            0x0301 => TlsVersion::TLSv1,
            0x0302 => TlsVersion::TLSv11,
            0x0303 => TlsVersion::TLSv12,
            _ => TlsVersion::UNKNOWN,
        }
    }
}


//  ------------  Helper macros and functions  ------------

/// Equivalent of try! macro to use in functions returning an `Option`.
macro_rules! tryopt {
    ($e:expr) => (match $e {
        Ok(val) => val,
        Err(_) => return None,
    });
}

/// Extracts the PHPSESSID cookie value.
fn extract_phpid<'a>(slr: &'a mut SliceReader) -> Option<(bool, &'a str)> {
    // only process HTTP responses, GET and POST requests
    let line = tryopt!(slr.read_line());
    if !line.starts_with(b"GET ") && !line.starts_with(b"POST ") && !line.starts_with(b"HTTP/") {
        return None;
    }

    // process the rest of the header
    while let Ok(line) = slr.read_line() {
        let line = line.trim();
        if line.len() == 0 {
            break; // finished parsing HTTP header
        }
        let (set_cookie, len) = {
            if line.starts_with(b"Cookie: ") {
                (false, 8)
            } else if line.starts_with(b"Set-Cookie: ") {
                (true, 12)
            } else {
                continue; // not a cookie header -> check next line
            }
        };
        // parse all cookies
        for cookie in line[len ..].split(|&e| e == b';') {
            let cookie = cookie.trim();
            if !cookie.starts_with(b"PHPSESSID=") {
                continue;
            }

            // cookie is a PHPSESSID: return it as an &str
            let phpid = &cookie[10 ..];
            return Some((set_cookie, tryopt!(str::from_utf8(phpid))));
        }
        break; // No PHPSESSID in cookies -> stop processing packet
    }
    None
}

/// Extract the TLS/SSL SNI value.
fn extract_tls_sni<'a>(slr: &'a mut SliceReader) -> Option<&'a str> {
    // TLS related constants
    const HANDSHAKE: u8 = 22;
    const CLIENT_HELLO: u8 = 1;
    const SERVER_NAME: u16 = 0x0000;

    // for each TLS record in the packet
    loop {
        // is it an SSL/TLS handshake with a supported version?
        let record_type = tryopt!(slr.read_u8());
        // stop processing packet if handshake is using an unsupported TLS version
        if TlsVersion::from_u16(tryopt!(slr.read_u16())) == TlsVersion::UNKNOWN {
            return None;
        }
        let len = tryopt!(slr.read_u16()) as usize;
        if record_type != HANDSHAKE {
            // not an handshake: skip current record and check next one
            slr.skip(len);
            continue;
        }

        let handshakes_end = slr.pos() + len;

        // for each handshake (usually only one)
        while slr.pos() < handshakes_end {
            let handshake_type = tryopt!(slr.read_u8());
            let len = tryopt!(slr.read_u24()) as usize; // handshake length
            if handshake_type != CLIENT_HELLO {
                // skip current handshake and check next one
                slr.skip(len);
                continue;
            }

            // check the TLS version requested by the client
            // might be different from the TLS version used during the handshake
            if TlsVersion::from_u16(tryopt!(slr.read_u16())) == TlsVersion::UNKNOWN {
                return None; // unsupported TLS version
            }
            
            // skip handshake fields we are not interested in
            slr.skip(32); // skip random
            let len = tryopt!(slr.read_u8()) as usize; // session ID length
            slr.skip(len); // skip session ID
            let len = tryopt!(slr.read_u16()) as usize; // cipher suite length
            slr.skip(len); // skip cipher suite
            let len = tryopt!(slr.read_u8()) as usize; // compression methods length
            slr.skip(len); // skip compression methods

            let len = tryopt!(slr.read_u16()) as usize; // extensions length
            let extensions_end = slr.pos() + len;

            // for each extension
            while slr.pos() < extensions_end {
                let extension_type = tryopt!(slr.read_u16());
                let len = tryopt!(slr.read_u16()) as usize;
                if extension_type != SERVER_NAME {
                    // skip current extension and check next one
                    slr.skip(len);
                    continue;
                }

                // this is a server-name extension: extract and return the server name field
                slr.skip(3); // skip list length and type
                let len = tryopt!(slr.read_u16()) as usize; // server name length
                let name = tryopt!(slr.read_bytes(len));
                return Some(tryopt!(str::from_utf8(name)));
            }
        }
    }
}


//  ------------  Plugin interface implementation  ------------

impl T2Plugin for RustExample {
    fn new() -> RustExample {
        RustExample {
            byte_count: 0,
            php_ids: HashSet::new(),
            tls_sni: String::new(),
        }
    }

    fn print_header() -> Header {
        let mut header = Header::new();

        // 1st column: throughput: non-repetitive double
        header.add_simple_col("On-wire throughput [byte/s]", "l2Throughput", false,
                              BinaryType::bt_double);

        // 2nd column: PHPSESSID values: repetitive compound (u8, string)
        // u8 value { 0: Cookie header sent by client, 1: Set-Cookie header sent by server }
        header.add_compound_col("PHP session IDs", "phpSessIds", true, 
                              &[BinaryType::bt_uint_8, BinaryType::bt_string]);

        // 3rd column: TLS SNI: non-repetitive string
        header.add_simple_col("TLS SNI", "tlsSni", false, BinaryType::bt_string);

        header
    }

    #[allow(unused_variables)]
    fn claim_l4_info(&mut self, packet: &Packet, flow: &mut Flow) {
        // update byte count
        self.byte_count += packet.packet_raw_len as u64;

        // process payload of TCP packets
        if packet.snap_l7_len > 0 && packet.l4_type == L4Type::TCP as u8 {
            let mut slr = SliceReader::new(packet.l7_header());

            // extract the PHPSESSID cookie
            if let Some((set_cookie, phpid)) = extract_phpid(&mut slr) {
                self.php_ids.insert((set_cookie, phpid.to_string()));
            }

            // revert slice reader at payload start
            let pos = slr.pos();
            slr.rewind(pos).unwrap();

            // extract the SSL/TLS SNI (server name identification) extension
            if self.tls_sni.len() == 0 {
                if let Some(sni) = extract_tls_sni(&mut slr) {
                    self.tls_sni = sni.to_string();
                }
            }
        }
    }

    fn on_flow_terminate(&mut self, flow: &mut Flow) {
        // 1st column: compute and output throughput
        let duration = flow.duration();
        if duration > 0f64 {
            let throughput = self.byte_count as f64 / duration;
            output_num(throughput);
        } else {
            output_num(0f64);
        }
        
        // 2nd column: output the PHPSESSID cookie values: repetitive compound (u8, string)
        let php_ids: Vec<(bool, String)> = self.php_ids.drain().collect();
        // repetitive values are prefixed by the number of repetitions as u32
        output_num(php_ids.len() as u32);
        for (set_cookie, php_id) in php_ids {
            output_num(set_cookie as u8);
            output_string(php_id);
        }

        // 3rd column: output TLS SNI
        output_string(&self.tls_sni);
    }
}

t2plugin!(RustExample);
