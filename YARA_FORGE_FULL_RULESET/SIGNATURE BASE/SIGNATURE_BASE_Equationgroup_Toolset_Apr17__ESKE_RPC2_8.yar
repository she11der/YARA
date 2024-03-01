rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17__ESKE_RPC2_8 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "694a1afc-7fea-58ac-b736-44957bbc0334"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L3400-L3416"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "1fa706fb7f138d679421fe6c5b29d6bf93893adc8bffe9dffaafa728c1b2d1d5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
		hash2 = "5c0896dbafc5d8cc19b1bc7924420b20ed5999ac5bee2cb5a91aada0ea01e337"

	strings:
		$s4 = "Fragment: Packet too small to contain RPC header" fullword ascii
		$s5 = "Fragment pickup: SmbNtReadX failed" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <700KB and 1 of them )
}
