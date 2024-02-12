rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Mofconfig_1_0_0___FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "d0d32e19-d004-5941-a5b3-0b4306565cf2"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L1716-L1729"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "a922eb01efa52601b72c3d91a26585504fcf706a9ed16a36328f94f5871b0b24"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c67a24fe2380331a101d27d6e69b82d968ccbae54a89a2629b6c135436d7bdb2"

	strings:
		$x1 = "[-] Get RemoteMOFTriggerPath error" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <50KB and all of them )
}