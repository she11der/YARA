rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17__ETBL_ETRE_10 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "7dfff868-cb66-51c0-a7c7-5cc872232b86"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L3441-L3458"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "bc30c62da7a7fd9144efef6f44c50552234f372c38c4479a024fbb0ca72530de"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "70db3ac2c1a10de6ce6b3e7a7890c37bffde006ea6d441f5de6d8329add4d2ef"
		hash2 = "e0f05f26293e3231e4e32916ad8a6ee944af842410c194fce8a0d8ad2f5c54b2"

	strings:
		$x1 = "Probe #2 usage: %s -i TargetIp -p TargetPort -r %d [-o TimeOut] -t Protocol -n IMailUserName -a IMailPassword" fullword ascii
		$x6 = "** RunExploit ** - EXCEPTION_EXECUTE_HANDLER : 0x%08X" fullword ascii
		$s19 = "Sending Implant Payload.. cEncImplantPayload size(%d)" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 1 of them )
}
