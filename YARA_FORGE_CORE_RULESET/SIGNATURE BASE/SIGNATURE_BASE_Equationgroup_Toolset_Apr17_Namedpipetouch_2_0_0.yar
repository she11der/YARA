rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Namedpipetouch_2_0_0 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "0a5519d7-9811-5159-8df2-0cb2995d5085"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L1781-L1800"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "63d4395db4672b7a146dbd285e42344fb895b38f67fa9f7885b73855d7211190"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "cb5849fcbc473c7df886828d225293ffbd8ee58e221d03b840fd212baeda6e89"
		hash2 = "043d1c9aae6be65f06ab6f0b923e173a96b536cf84e57bfd7eeb9034cd1df8ea"

	strings:
		$s1 = "[*] Summary: %d pipes found" fullword ascii
		$s3 = "[+] Testing %d pipes" fullword ascii
		$s6 = "[-] Error on SMB startup, aborting" fullword ascii
		$s12 = "92a761c29b946aa458876ff78375e0e28bc8acb0" fullword ascii
		$op1 = { 68 10 10 40 00 56 e8 e1 }

	condition:
		( uint16(0)==0x5a4d and filesize <40KB and 2 of them )
}
