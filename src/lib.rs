use pyo3::prelude::*;
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// The pattern might include a directory path that
// is not the current working directory and may not
// exist, so create the parent directories if needed.
fn ensure_parent(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

// Given the requested file naming pattern, replaces placeholders
// appropriately to generate a presumably unique file name.
fn format_path(pattern: &str, index: usize) -> PathBuf {
    PathBuf::from(pattern.replace("{index}", &index.to_string()))
}

// PCAP magic values
const PCAP_MAGIC_USEC_BE: u32 = 0xA1B2C3D4;
const PCAP_MAGIC_USEC_LE: u32 = 0xD4C3B2A1;
const PCAP_MAGIC_NSEC_BE: u32 = 0xA1B23C4D;
const PCAP_MAGIC_NSEC_LE: u32 = 0x4D3CB2A1;

// PCAPNG constants
const PCAPNG_BLOCK_SHB: u32 = 0x0A0D0D0A; // Section Header Block
const PCAPNG_BLOCK_SPB: u32 = 0x00000003; // Simple Packet Block
const PCAPNG_BLOCK_EPB: u32 = 0x00000006; // Enhanced Packet Block

#[derive(Clone, Copy)]
enum Endian {
    Le,
    Be,
}

fn read_exact_into<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<()> {
    r.read_exact(buf)
}

fn read_u32(buf: &[u8], e: Endian) -> u32 {
    let arr = [buf[0], buf[1], buf[2], buf[3]];
    match e {
        Endian::Le => u32::from_le_bytes(arr),
        Endian::Be => u32::from_be_bytes(arr),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputFormat {
    Pcap,
    PcapNg,
}

fn detect_format<R: Read>(r: &mut R) -> io::Result<(InputFormat, Vec<u8>)> {
    // Returns the format and the number of bytes that have already been read

    // Extract the first 4 bytes (our magic bytes)
    let mut magic_bytes = [0u8; 4];
    read_exact_into(r, &mut magic_bytes)?;

    // Detect if the format is pcapng - here is the magic is
    // palindromic, so the endianness does not affect detection unlike pcap
    let magic = u32::from_be_bytes(magic_bytes);
    if magic == PCAPNG_BLOCK_SHB {
        return Ok((InputFormat::PcapNg, magic_bytes.to_vec()));
    }

    // Detect if the format is pcap - unlike pcapng, the endianness
    // affects detection, and we must check against all endian readings.
    // First, check for little-endian.
    let le_magic = u32::from_le_bytes(magic_bytes);
    if matches!(le_magic, PCAP_MAGIC_USEC_LE | PCAP_MAGIC_NSEC_LE) {
        return Ok((InputFormat::Pcap, magic_bytes.to_vec()));
    }

    // Check for big-endian.
    let be_magic = u32::from_be_bytes(magic_bytes);
    if matches!(be_magic, PCAP_MAGIC_USEC_BE | PCAP_MAGIC_NSEC_BE) {
        return Ok((InputFormat::Pcap, magic_bytes.to_vec()));
    }

    // If we get here, it seems we failed to detect the format.
    // It may as well not be a pcap nor pcapng file at all!
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "Unknown input format: not pcap/pcapng",
    ))
}

struct RotatingOutput {
    pattern: String,
    rotate_every: Option<Duration>,
    max_packets: Option<usize>,
    started: Instant,
    index: usize,
    packets_written_in_file: usize,
    file: Option<File>,
    // pcap classic requires a global header to prepend to new files
    pcap_global_header: Option<Vec<u8>>,
    // pcapng requires preamble blocks (SHB + IDBs + ...)
    pcapng_preamble: Option<Vec<u8>>,
}

impl RotatingOutput {
    fn new(pattern: String, rotate_every: Option<Duration>, max_packets: Option<usize>) -> Self {
        Self {
            pattern,
            rotate_every,
            max_packets,
            started: Instant::now(),
            index: 0,
            packets_written_in_file: 0,
            file: None,
            pcap_global_header: None,
            pcapng_preamble: None,
        }
    }

    fn set_pcap_global_header(&mut self, hdr: Vec<u8>) {
        self.pcap_global_header = Some(hdr);
    }

    fn set_pcapng_preamble(&mut self, pre: Vec<u8>) {
        self.pcapng_preamble = Some(pre);
    }

    fn should_rotate(&self) -> bool {
        if self.file.is_none() {
            return true;
        }
        if let Some(dur) = self.rotate_every {
            if self.started.elapsed() >= dur {
                return true;
            }
        }
        if let Some(maxp) = self.max_packets {
            if self.packets_written_in_file >= maxp {
                return true;
            }
        }
        false
    }

    fn open_new_file(&mut self, is_pcapng: bool) -> io::Result<()> {
        let path = format_path(&self.pattern, self.index);
        ensure_parent(&path)?;
        let mut f = File::create(&path)?;

        if is_pcapng {
            if let Some(pre) = &self.pcapng_preamble {
                f.write_all(pre)?;
            }
        } else {
            if let Some(h) = &self.pcap_global_header {
                f.write_all(h)?;
            }
        }

        self.file = Some(f);
        self.started = Instant::now();
        self.packets_written_in_file = 0;
        self.index += 1;
        Ok(())
    }

    fn maybe_rotate(&mut self, is_pcapng: bool) -> io::Result<()> {
        if self.should_rotate() {
            self.open_new_file(is_pcapng)?;
        }
        Ok(())
    }

    fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        if let Some(f) = &mut self.file {
            f.write_all(data)
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "file not opened"))
        }
    }

    fn inc_packet(&mut self) {
        self.packets_written_in_file += 1;
    }
}

fn process_pcap<R: Read>(
    mut reader: R,
    already_read: Vec<u8>,
    output: &mut RotatingOutput,
) -> io::Result<()> {
    // The first 4 bytes of the global header are in
    // `already_read`, we must them extract the remainder of it.
    let mut global_hdr = already_read;
    let mut remaining_global_hdr = [0u8; 24 - 4];
    read_exact_into(&mut reader, &mut remaining_global_hdr)?;
    global_hdr.extend_from_slice(&remaining_global_hdr);

    // Determine endianness based on the magic
    let magic_be = u32::from_be_bytes([global_hdr[0], global_hdr[1], global_hdr[2], global_hdr[3]]);
    let e = if magic_be == PCAP_MAGIC_USEC_BE || magic_be == PCAP_MAGIC_NSEC_BE {
        Endian::Be
    } else {
        Endian::Le
    };

    output.set_pcap_global_header(global_hdr.clone());
    output.maybe_rotate(false)?; // ensure file open and header written

    loop {
        let mut packet_header = [0u8; 16];
        match reader.read_exact(&mut packet_header) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }

        // Determine the data length, then read the data.
        let incl_len = read_u32(&packet_header[8..12], e) as usize;
        let mut data = vec![0u8; incl_len];
        read_exact_into(&mut reader, &mut data)?;

        // Rotate if needed before writing this packet
        output.maybe_rotate(false)?;

        output.write_all(&packet_header)?;
        output.write_all(&data)?;
        output.inc_packet();
    }
    Ok(())
}

fn process_pcapng<R: Read>(
    mut reader: R,
    first4: Vec<u8>,
    output: &mut RotatingOutput,
) -> io::Result<()> {
    // Read the rest of the first block header (total length) to get full SHB, detect endianness and capture preamble until the first packet block
    let mut hdr8 = [0u8; 4]; // the length field
    read_exact_into(&mut reader, &mut hdr8)?;
    // Guess length endianness heuristically
    let len_le = u32::from_le_bytes(hdr8);
    let len_be = u32::from_be_bytes(hdr8);
    let total_len = if len_le >= 28 && len_le % 4 == 0 && len_le < (1 << 26) {
        len_le
    } else {
        len_be
    };
    let mut shb = Vec::with_capacity(total_len as usize);
    shb.extend_from_slice(&first4); // block type
    shb.extend_from_slice(&hdr8); // total length (unknown endian but as read)
    let mut rest = vec![0u8; total_len as usize - 8];
    read_exact_into(&mut reader, &mut rest)?;
    shb.extend_from_slice(&rest);

    // Determine endianness from byte-order magic at offset 8 from block start (after type and length)
    let bom_off = 8; // within the block
    let bom = u32::from_le_bytes([
        shb[bom_off],
        shb[bom_off + 1],
        shb[bom_off + 2],
        shb[bom_off + 3],
    ]);
    let endian = if bom == 0x1A2B3C4D {
        Endian::Le
    } else {
        Endian::Be
    };

    // Preamble: SHB + all non-packet blocks until the first packet
    let mut preamble = Vec::new();
    preamble.extend_from_slice(&shb);

    // Now read blocks until we hit a packet block; collect all non-packet
    // blocks into the preamble, but defer writing anything until we open the file
    let mut encountered_packet = false;

    loop {
        // peek next 8 bytes
        let mut head = [0u8; 8];
        match reader.read_exact(&mut head) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                // End of the file without packets; still write preamble once to create an empty file
                output.set_pcapng_preamble(preamble.clone());
                output.maybe_rotate(true)?;
                return Ok(());
            }
            Err(e) => return Err(e),
        }
        let block_type = read_u32(&head[0..4], endian);
        let block_length = read_u32(&head[4..8], endian) as usize;
        if block_length < 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid pcapng block length",
            ));
        }
        let mut body_plus_tail = vec![0u8; block_length - 8];
        read_exact_into(&mut reader, &mut body_plus_tail)?;
        let mut full = Vec::with_capacity(block_length);
        full.extend_from_slice(&head);
        full.extend_from_slice(&body_plus_tail);

        let is_packet_block = block_type == PCAPNG_BLOCK_EPB || block_type == PCAPNG_BLOCK_SPB;
        if !encountered_packet && !is_packet_block {
            preamble.extend_from_slice(&full);
            continue;
        }
        if !encountered_packet && is_packet_block {
            encountered_packet = true;
            output.set_pcapng_preamble(preamble.clone());
            output.maybe_rotate(true)?;
        }

        // Before writing a packet block, maybe rotate
        if is_packet_block {
            output.maybe_rotate(true)?;
        }

        output.write_all(&full)?;
        if is_packet_block {
            output.inc_packet();
        }
    }
}

#[pyfunction(signature = (output_pattern, rotate_seconds=None, max_packets=None))]
fn run_stream(
    output_pattern: String,
    rotate_seconds: Option<u64>,
    max_packets: Option<usize>,
) -> PyResult<()> {
    let rotate_every = rotate_seconds.map(|s| Duration::from_secs(s.max(1)));
    let mut output = RotatingOutput::new(output_pattern, rotate_every, max_packets);

    let stdin = io::stdin();
    let mut locked = BufReader::new(stdin.lock());

    // Detect format
    let (fmt, first_bytes) = detect_format(&mut locked).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("Failed to detect format: {e}"))
    })?;

    let res = match fmt {
        InputFormat::Pcap => process_pcap(locked, first_bytes, &mut output),
        InputFormat::PcapNg => process_pcapng(locked, first_bytes, &mut output),
    };

    res.map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("I/O error: {e}")))
}

use pyo3::{Bound, types::PyModule};
#[pymodule]
#[pyo3(name = "runtime")]
fn runtime(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(run_stream, m)?)?;
    Ok(())
}
