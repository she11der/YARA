rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17__ELV_ESKE_13___FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "8bc3c47c-7357-5692-86aa-e43b40f8c1ab"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L3500-L3516"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "0a1859266b859d4da660a7fc7d0015954ff100c39b941b5461ba0c99b5103547"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "f7fad44560bc8cc04f03f1d30b6e1b4c5f049b9a8a45464f43359cbe4d1ce86f"
		hash2 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"

	strings:
		$x1 = "Skip call to PackageRideArea().  Payload has already been packaged. Options -x and -q ignored." fullword ascii
		$s2 = "ERROR: pGvars->pIntRideAreaImplantPayload is NULL" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <600KB and 1 of them )
}