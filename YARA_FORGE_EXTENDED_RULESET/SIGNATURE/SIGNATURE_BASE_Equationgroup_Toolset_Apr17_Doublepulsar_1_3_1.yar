rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Doublepulsar_1_3_1 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "99711157-58eb-5ec0-bb9f-bf953cd10125"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L1619-L1634"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "1b7ed9dbd4312541bd4d939602f63ce1d909729cce1845b018be6a07a9cb7fe2"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "15ffbb8d382cd2ff7b0bd4c87a7c0bffd1541c2fe86865af445123bc0b770d13"

	strings:
		$x1 = "[+] Ping returned Target architecture: %s - XOR Key: 0x%08X" fullword ascii
		$x2 = "[.] Sending shellcode to inject DLL" fullword ascii
		$x3 = "[-] Error setting ShellcodeFile name" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and 1 of them )
}
