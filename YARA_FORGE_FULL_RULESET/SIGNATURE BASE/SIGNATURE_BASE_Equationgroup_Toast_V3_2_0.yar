rule SIGNATURE_BASE_Equationgroup_Toast_V3_2_0 : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file toast_v3.2.0.1-linux"
		author = "Florian Roth (Nextron Systems)"
		id = "776014ae-be94-5d81-bceb-fefb67ee1994"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L190-L205"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "a505eaafb6882e2701fe0a9b8712f85c1073d83291436eeaa7f4c52876d12359"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2ce2d16d24069dc29cf1464819a9dc6deed38d1e5ffc86d175b06ddb691b648b"

	strings:
		$x2 = "Del --- Usage: %s -l file -w wtmp -r user" fullword ascii
		$s5 = "Roasting ->%s<- at ->%d:%d<-" ascii
		$s6 = "rbnoil -Roasting ->" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <50KB and 1 of them )
}
