rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17__ELV_ESKE_ETBL_ETRE_EVFR_11___FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "d6848065-377b-5eda-821d-d2cc16f483cc"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L3460-L3479"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "8d43aa4823de248308597bd02cd27e598808b94e1ad7348ddb9e27d8a37ac426"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "f7fad44560bc8cc04f03f1d30b6e1b4c5f049b9a8a45464f43359cbe4d1ce86f"
		hash2 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
		hash3 = "70db3ac2c1a10de6ce6b3e7a7890c37bffde006ea6d441f5de6d8329add4d2ef"
		hash4 = "e0f05f26293e3231e4e32916ad8a6ee944af842410c194fce8a0d8ad2f5c54b2"
		hash5 = "c5e119ff7b47333f415aea1d2a43cb6cb322f8518562cfb9b90399cac95ac674"

	strings:
		$x1 = "Target is vulnerable" fullword ascii
		$x2 = "Target is NOT vulnerable" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and 1 of them )
}