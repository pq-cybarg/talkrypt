// Representative nested-heap decoder (mirrors talkrypt's LinkageProof::decode return
// shape: Vec<Struct{Vec<u8>, Vec<u8>}>) — the class Kani/CBMC could not discharge. Verus
// proves TOTALITY (no panic / overflow / OOB) for ALL inputs. See docs/fv-heap-decoder-spike.md.
use vstd::prelude::*;
verus! {
pub struct Item { pub label: Vec<u8>, pub data: Vec<u8> }
pub struct Doc { pub items: Vec<Item> }
pub fn decode(bytes: &[u8]) -> Option<Doc> {
    if bytes.len() == 0 { return None; }
    let n: usize = bytes[0] as usize;
    let mut pos: usize = 1;
    let mut items: Vec<Item> = Vec::new();
    let mut i: usize = 0;
    while i < n
        invariant pos <= bytes.len(), i <= n, decreases n - i,
    {
        if pos >= bytes.len() { return None; }
        let ll: usize = bytes[pos] as usize; pos = pos + 1;
        if ll > bytes.len() - pos { return None; }
        let mut label: Vec<u8> = Vec::new();
        let mut j: usize = 0;
        while j < ll
            invariant pos + ll <= bytes.len(), pos <= bytes.len(), j <= ll, decreases ll - j,
        { label.push(bytes[pos + j]); j = j + 1; }
        pos = pos + ll;
        if pos >= bytes.len() { return None; }
        let dl: usize = bytes[pos] as usize; pos = pos + 1;
        if dl > bytes.len() - pos { return None; }
        let mut data: Vec<u8> = Vec::new();
        let mut k: usize = 0;
        while k < dl
            invariant pos + dl <= bytes.len(), pos <= bytes.len(), k <= dl, decreases dl - k,
        { data.push(bytes[pos + k]); k = k + 1; }
        pos = pos + dl;
        items.push(Item { label, data }); i = i + 1;
    }
    Some(Doc { items })
}
} // verus!
fn main() {}
