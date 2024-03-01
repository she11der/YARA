import "pe"

rule SIGNATURE_BASE_EQGRP_BPATROL_2201 : FILE
{
	meta:
		description = "EQGRP Toolset Firewall - file BPATROL-2201.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "864a346c-e8aa-5c66-9867-faccb14b8bee"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L689-L706"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "a2e9aa4627924c99dd3a342174855df3f0d545a67fd2293ca5601eeae70ae010"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "aa892750b893033eed2fedb2f4d872f79421174eb217f0c34a933c424ae66395"

	strings:
		$s1 = "dumpConfig" fullword ascii
		$s2 = "getstatusHandler" fullword ascii
		$s3 = ".got_loader" fullword ascii
		$s4 = "xtractdata" fullword ascii
		$s5 = "KEEPGOING" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <40KB and all of them )
}
