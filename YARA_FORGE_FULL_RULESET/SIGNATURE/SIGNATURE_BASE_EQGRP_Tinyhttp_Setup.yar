import "pe"

rule SIGNATURE_BASE_EQGRP_Tinyhttp_Setup : FILE
{
	meta:
		description = "EQGRP Toolset Firewall - file tinyhttp_setup.sh"
		author = "Florian Roth (Nextron Systems)"
		id = "71dcc48f-f551-5596-9f03-dbbae470a62b"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L568-L584"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "0d560206e634f3bfeffe5b7de3edf02f6c76443ffb5c0de37180e63276a19457"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "3d12c83067a9f40f2f5558d3cf3434bbc9a4c3bb9d66d0e3c0b09b9841c766a0"

	strings:
		$x1 = "firefox http://127.0.0.1:8000/$_name" fullword ascii
		$x2 = "What is the name of your implant:" fullword ascii
		$x3 = "killall thttpd" fullword ascii
		$x4 = "copy http://<IP>:80/$_name flash:/$_name" fullword ascii

	condition:
		( uint16(0)==0x2123 and filesize <2KB and 1 of ($x*)) or ( all of them )
}
