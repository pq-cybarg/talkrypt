module DecodeTotality
/// Machine-checked TOTALITY of a nested wire decoder, in F* (route 2 of the FV spike,
/// docs/fv-heap-decoder-spike.md). talkrypt's chain-embedding decoders return nested
/// heap (Vec<Struct{String,Vec}>) which CBMC/Kani cannot prove total -- it models
/// construct+drop of the nested heap expensively. The Aeneas route sidesteps this: it
/// turns borrow-checked Rust into a PURE functional model with no heap (no aliasing),
/// then F* proves it. Here that endpoint is reached directly -- the same decode grammar
/// as a TOTAL F* function. F* accepting it in the `Tot` effect IS the proof of totality
/// (guaranteed termination + no partial/failing operation) for ALL inputs. Verified with
/// the same F* that discharges GroupAuth.fst.
module U8 = FStar.UInt8
open FStar.Seq

/// Decode `n` (label_len, data_len) items from `b` starting at `pos`; returns the final
/// position or None on a short read. Every `index` is bounds-guarded; the recursion
/// decreases on `n`, so the function is provably terminating and total.
let rec decode_items (b: seq U8.t) (n: nat) (pos: nat)
  : Tot (option nat) (decreases n)
  = if n = 0 then Some pos
    else if pos >= length b then None
    else begin
      let ll = U8.v (index b pos) in
      let pos1 = pos + 1 in
      if ll > length b - pos1 then None
      else begin
        let pos2 = pos1 + ll in
        if pos2 >= length b then None
        else begin
          let dl = U8.v (index b pos2) in
          let pos3 = pos2 + 1 in
          if dl > length b - pos3 then None
          else decode_items b (n - 1) (pos3 + dl)
        end
      end
    end

let decode (b: seq U8.t) : Tot (option nat)
  = if length b = 0 then None
    else decode_items b (U8.v (index b 0)) 1
