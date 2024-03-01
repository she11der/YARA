rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Ifconfig_Target : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "db8ec377-a9f6-5d75-a123-aa0365d98065"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L2706-L2722"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "e88f589bed7830a1be81c85c9eb77b7f5c14bef2f0f1b3be6293aa9c5e870278"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "1ebfc0ce7139db43ddacf4a9af2cb83a407d3d1221931d359ee40588cfd0d02b"

	strings:
		$s1 = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%hs" fullword wide
		$op1 = { 0f be 37 85 f6 0f 85 4e ff ff ff 45 85 ed 74 21 }
		$op2 = { 4c 8d 44 24 34 48 8d 57 08 41 8d 49 07 e8 a6 4b }

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and all of them )
}
