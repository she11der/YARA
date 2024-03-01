import "pe"

rule SIGNATURE_BASE_EQGRP_Extrabacon_Output
{
	meta:
		description = "EQGRP Toolset Firewall - Extrabacon exploit output"
		author = "Florian Roth (Nextron Systems)"
		id = "b2070ed7-e95a-534a-8f27-63c5ca9251b4"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L1274-L1290"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "5e71a4380dd30e68d89add1718976d3207a161d2d61fd4c3250fc4b10a0f53a0"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "|###[ SNMPresponse ]###" fullword ascii
		$s2 = "[+] generating exploit for exec mode pass-disable" fullword ascii
		$s3 = "[+] building payload for mode pass-disable" fullword ascii
		$s4 = "[+] Executing:  extrabacon" fullword ascii
		$s5 = "appended AAAADMINAUTH_ENABLE payload" fullword ascii

	condition:
		2 of them
}
