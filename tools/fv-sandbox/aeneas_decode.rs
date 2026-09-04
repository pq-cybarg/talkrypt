// Self-contained decoder for the Aeneas -> F* pipeline. Charon translates a crate like
// `cargo build`; the REAL talkrypt LinkageProof pulls in async + external crypto crates
// (ml-dsa/ml-kem) that Charon cannot ingest, so this extracted, dependency-free form is
// the Aeneas-tractable target. Aeneas turns it into a pure functional F* model (the heap
// disappears via the borrow checker's no-aliasing guarantee); F* then proves totality.
#![no_std]

pub struct Item { pub label_len: usize, pub data_len: usize }
pub struct Doc { pub n: usize }

pub fn decode(bytes: &[u8]) -> Option<Doc> {
    if bytes.is_empty() { return None; }
    let n: usize = bytes[0] as usize;
    let mut pos: usize = 1;
    let mut i: usize = 0;
    while i < n {
        if pos >= bytes.len() { return None; }
        let ll: usize = bytes[pos] as usize; pos += 1;
        if ll > bytes.len() - pos { return None; }
        pos += ll;
        if pos >= bytes.len() { return None; }
        let dl: usize = bytes[pos] as usize; pos += 1;
        if dl > bytes.len() - pos { return None; }
        pos += dl;
        i += 1;
    }
    Some(Doc { n })
}
