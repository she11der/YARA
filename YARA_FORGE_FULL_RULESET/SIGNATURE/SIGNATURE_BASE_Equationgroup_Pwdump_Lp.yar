import "pe"

rule SIGNATURE_BASE_Equationgroup_Pwdump_Lp : FILE
{
	meta:
		description = "EquationGroup Malware - file pwdump_Lp.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "6f356f13-9ec1-5dd9-91b2-6a3071398e81"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L1821-L1834"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "7381ffd9b2b720fa99d52bc5805fea942e5a966bf3fd611f1a80a875edd06dad"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "fda57a2ba99bc610d3ff71b2d0ea2829915eabca168df99709a8fdd24288c5e5"

	strings:
		$x1 = "PWDUMP - - ERROR - -" wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}
