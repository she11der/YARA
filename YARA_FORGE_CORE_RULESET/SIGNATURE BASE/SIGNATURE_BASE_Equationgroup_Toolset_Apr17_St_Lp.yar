rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_St_Lp : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "2d4ee801-c7f4-5476-8368-89aa2863ba96"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L2238-L2254"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "38a48a931856e0eb8e16b7902f5e494b50f8895d4221b5359fc3339d1b52eb8e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "3b6f756cca096548dcad2b6c241c1dafd16806c060bec82a530f4d38755286a2"

	strings:
		$x1 = "Previous command: set injection processes (status=0x%x)" fullword ascii
		$x2 = "Secondary injection process is <null> [no secondary process will be used]" fullword ascii
		$x3 = "Enter the address to be used as the spoofed IP source address (xxx.xxx.xxx.xxx) -> " fullword ascii
		$x4 = "E: Execute a Command on the Implant" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 1 of them )
}
