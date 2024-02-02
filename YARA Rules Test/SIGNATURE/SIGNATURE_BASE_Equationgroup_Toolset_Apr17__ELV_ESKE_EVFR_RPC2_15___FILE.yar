rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17__ELV_ESKE_EVFR_RPC2_15___FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "f671a10d-f0b8-5343-97b5-e60b7f2f0acf"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L3537-L3555"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "6c61d17e1a985deb31bd6e1d603283e77df477b52fce9eb8b6cb4e99b2f9c4dc"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "f7fad44560bc8cc04f03f1d30b6e1b4c5f049b9a8a45464f43359cbe4d1ce86f"
		hash2 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
		hash3 = "c5e119ff7b47333f415aea1d2a43cb6cb322f8518562cfb9b90399cac95ac674"
		hash4 = "5c0896dbafc5d8cc19b1bc7924420b20ed5999ac5bee2cb5a91aada0ea01e337"

	strings:
		$x1 = "** SendAndReceive ** - EXCEPTION_EXECUTE_HANDLER" fullword ascii
		$s8 = "Binding to RPC Interface %s over named pipe" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and 1 of them )
}