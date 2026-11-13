# Machine-checked formal verification of talkrypt's cryptographic core.
#   * F*        — symbolic group-message authentication theorems (GroupAuth.fst),
#                 identity-chain verification soundness / impersonation resistance /
#                 revocation (IdentityChain.fst), pairwise Double Ratchet forward
#                 secrecy + post-compromise security (RatchetFS.fst), handshake mutual
#                 authentication + session-key secrecy (Handshake.fst), TreeKEM group
#                 key-schedule PCS/FS (TreeKemKS.fst), nested decoder totality
#                 (DecodeTotality.fst)
#   * EasyCrypt — computational, QROM-sound reductions:
#                   GroupAuthQROM.ec      (auth => EUF-CMA, all acceptance routes)
#                   ConfidentialityQROM.ec (confidentiality => KEM IND-CCA + DEM)
#                   LeafSigDeriveUnlink.ec (derived leaf keys: key-hiding + cross-chat
#                                           unlinkability => PRF security of mac_kdf)
# Requires fstar.exe and easycrypt on PATH. Run: `make verify`.
FSTAR     ?= fstar.exe
EASYCRYPT ?= easycrypt

.PHONY: verify fstar easycrypt clean
verify: fstar easycrypt

fstar:
	$(FSTAR) GroupAuth.fst
	$(FSTAR) IdentityChain.fst
	$(FSTAR) RatchetFS.fst
	$(FSTAR) Handshake.fst
	$(FSTAR) TreeKemKS.fst
	$(FSTAR) DecodeTotality.fst

easycrypt:
	$(EASYCRYPT) compile GroupAuthQROM.ec
	$(EASYCRYPT) compile ConfidentialityQROM.ec
	$(EASYCRYPT) compile LeafSigDeriveUnlink.ec

clean:
	rm -f *.checked *.krml *.eco
