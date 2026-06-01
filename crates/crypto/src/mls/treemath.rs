//! RFC 9420 (MLS) tree math — the canonical left-balanced binary tree node
//! arithmetic, on the array layout where a tree with `n` leaves has `2n-1`
//! nodes, leaves at even indices and parents at odd indices.
//!
//! This is real RFC 9420, **validated against the MLS working group's official
//! `tree-math` test vectors** (see the test below). It is the structural
//! foundation of the standards-track MLS group; `treekem.rs` remains talkrypt's
//! shipped PQ group, while this module brings the actual MLS layout online.

/// `floor(log2(x))`, with `log2(0) == 0` per the RFC's helper.
pub fn log2(x: u32) -> u32 {
    if x == 0 {
        return 0;
    }
    let mut k = 0;
    while (x >> k) > 0 {
        k += 1;
    }
    k - 1
}

/// The level of a node: 0 for leaves, else the count of trailing one-bits.
pub fn level(x: u32) -> u32 {
    if x & 1 == 0 {
        return 0;
    }
    let mut k = 0;
    while (x >> k) & 1 == 1 {
        k += 1;
    }
    k
}

/// Number of nodes in a tree with `n` leaves (`2n-1`, or 0 if empty).
pub fn node_width(n: u32) -> u32 {
    if n == 0 {
        0
    } else {
        2 * (n - 1) + 1
    }
}

/// Index of the root node for `n` leaves.
pub fn root(n: u32) -> u32 {
    let w = node_width(n);
    (1 << log2(w)) - 1
}

/// Left child of an intermediate node. Panics on a leaf.
pub fn left(x: u32) -> u32 {
    let k = level(x);
    assert!(k != 0, "leaf node has no children");
    x ^ (1 << (k - 1))
}

/// Right child of an intermediate node. Panics on a leaf.
pub fn right(x: u32) -> u32 {
    let k = level(x);
    assert!(k != 0, "leaf node has no children");
    x ^ (3 << (k - 1))
}

fn parent_step(x: u32) -> u32 {
    let k = level(x);
    let b = (x >> (k + 1)) & 1;
    (x | (1 << k)) ^ (b << (k + 1))
}

/// Parent of a node in a tree of `n` leaves. `None` for the root.
pub fn parent(x: u32, n: u32) -> Option<u32> {
    if x == root(n) {
        return None;
    }
    let mut p = parent_step(x);
    let w = node_width(n);
    while p >= w {
        p = parent_step(p);
    }
    Some(p)
}

/// Sibling of a node in a tree of `n` leaves. `None` for the root.
pub fn sibling(x: u32, n: u32) -> Option<u32> {
    let p = parent(x, n)?;
    Some(if x < p { right(p) } else { left(p) })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One element of the RFC 9420 `tree-math` test vector.
    struct Vec9420 {
        n_leaves: u32,
        n_nodes: u32,
        root: u32,
        left: &'static [Option<u32>],
        right: &'static [Option<u32>],
        parent: &'static [Option<u32>],
        sibling: &'static [Option<u32>],
    }

    // Official vectors (mlswg/mls-implementations test-vectors/tree-math.json),
    // for n_leaves 1, 2, 4, 8. `null` -> None.
    const VECTORS: &[Vec9420] = &[
        Vec9420 {
            n_leaves: 1,
            n_nodes: 1,
            root: 0,
            left: &[None],
            right: &[None],
            parent: &[None],
            sibling: &[None],
        },
        Vec9420 {
            n_leaves: 2,
            n_nodes: 3,
            root: 1,
            left: &[None, Some(0), None],
            right: &[None, Some(2), None],
            parent: &[Some(1), None, Some(1)],
            sibling: &[Some(2), None, Some(0)],
        },
        Vec9420 {
            n_leaves: 4,
            n_nodes: 7,
            root: 3,
            left: &[None, Some(0), None, Some(1), None, Some(4), None],
            right: &[None, Some(2), None, Some(5), None, Some(6), None],
            parent: &[Some(1), Some(3), Some(1), None, Some(5), Some(3), Some(5)],
            sibling: &[Some(2), Some(5), Some(0), None, Some(6), Some(1), Some(4)],
        },
        Vec9420 {
            n_leaves: 8,
            n_nodes: 15,
            root: 7,
            left: &[
                None,
                Some(0),
                None,
                Some(1),
                None,
                Some(4),
                None,
                Some(3),
                None,
                Some(8),
                None,
                Some(9),
                None,
                Some(12),
                None,
            ],
            right: &[
                None,
                Some(2),
                None,
                Some(5),
                None,
                Some(6),
                None,
                Some(11),
                None,
                Some(10),
                None,
                Some(13),
                None,
                Some(14),
                None,
            ],
            parent: &[
                Some(1),
                Some(3),
                Some(1),
                Some(7),
                Some(5),
                Some(3),
                Some(5),
                None,
                Some(9),
                Some(11),
                Some(9),
                Some(7),
                Some(13),
                Some(11),
                Some(13),
            ],
            sibling: &[
                Some(2),
                Some(5),
                Some(0),
                Some(11),
                Some(6),
                Some(1),
                Some(4),
                None,
                Some(10),
                Some(13),
                Some(8),
                Some(3),
                Some(14),
                Some(9),
                Some(12),
            ],
        },
    ];

    #[test]
    fn matches_rfc9420_tree_math_vectors() {
        for v in VECTORS {
            assert_eq!(
                node_width(v.n_leaves),
                v.n_nodes,
                "n_nodes n={}",
                v.n_leaves
            );
            assert_eq!(root(v.n_leaves), v.root, "root n={}", v.n_leaves);
            for x in 0..v.n_nodes {
                let xi = x as usize;
                // left/right only defined for intermediate (odd) nodes.
                if level(x) != 0 {
                    assert_eq!(Some(left(x)), v.left[xi], "left {x} n={}", v.n_leaves);
                    assert_eq!(Some(right(x)), v.right[xi], "right {x} n={}", v.n_leaves);
                } else {
                    assert_eq!(v.left[xi], None);
                    assert_eq!(v.right[xi], None);
                }
                assert_eq!(
                    parent(x, v.n_leaves),
                    v.parent[xi],
                    "parent {x} n={}",
                    v.n_leaves
                );
                assert_eq!(
                    sibling(x, v.n_leaves),
                    v.sibling[xi],
                    "sibling {x} n={}",
                    v.n_leaves
                );
            }
        }
    }

    #[test]
    fn sibling_is_involution_on_full_trees() {
        // In a *full* (power-of-two) tree the sibling relation is symmetric.
        // (In MLS's truncated left-balanced trees it need not be, by design.)
        for &n in &[1u32, 2, 4, 8, 16, 32, 64] {
            for x in 0..node_width(n) {
                if let Some(s) = sibling(x, n) {
                    assert_eq!(sibling(s, n), Some(x), "n={n} x={x}");
                }
            }
        }
    }
}
