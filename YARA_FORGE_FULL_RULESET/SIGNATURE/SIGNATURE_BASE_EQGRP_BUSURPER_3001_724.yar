import "pe"

rule SIGNATURE_BASE_EQGRP_BUSURPER_3001_724 : FILE
{
	meta:
		description = "EQGRP Toolset Firewall - file BUSURPER-3001-724.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "006877e9-1e73-5a27-8b3a-bca3513a2035"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L525-L540"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "531f7039290b386f070378cb4ba49a57b5031fb16b3972b61f4fb904770fc4ac"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "6b558a6b8bf3735a869365256f9f2ad2ed75ccaa0eefdc61d6274df4705e978b"

	strings:
		$s1 = "IMPLANT" fullword ascii
		$s2 = "KEEPGOING" fullword ascii
		$s3 = "upgrade_implant" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <200KB and 2 of them ) or ( all of them )
}
