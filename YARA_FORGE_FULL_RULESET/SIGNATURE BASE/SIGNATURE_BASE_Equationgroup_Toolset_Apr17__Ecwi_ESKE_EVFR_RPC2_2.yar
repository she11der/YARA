rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17__Ecwi_ESKE_EVFR_RPC2_2 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "6c653b0a-fda4-51d6-bf90-bd637547fe47"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L3317-L3336"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "73522034c6588fee090eff87602568371562bdbcbe781ee6e152f3b854514690"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "c4152f65e45ff327dade50f1ac3d3b876572a66c1ce03014f2877cea715d9afd"
		hash2 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
		hash3 = "c5e119ff7b47333f415aea1d2a43cb6cb322f8518562cfb9b90399cac95ac674"
		hash4 = "5c0896dbafc5d8cc19b1bc7924420b20ed5999ac5bee2cb5a91aada0ea01e337"

	strings:
		$s1 = "Target is share name" fullword ascii
		$s2 = "Could not make UdpNetbios header -- bailing" fullword ascii
		$s3 = "Request non-NT session key" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and all of them )
}
