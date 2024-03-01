import "pe"

rule SIGNATURE_BASE_Equationgroup_Modifyauthentication_Implant : FILE
{
	meta:
		description = "EquationGroup Malware - file modifyAuthentication_Implant.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "990035c5-cd9c-59e0-b244-e2caafd2561f"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L1644-L1661"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "8bdc4c9e9a3e327bb55781670d8f373d5a8904ccd47cc4b67673c47a76c54927"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "e1dff24af5bfc991dca21b4e3a19ffbc069176d674179eef691afc6b1ac6f805"

	strings:
		$s1 = "LSASS.EXE" fullword wide
		$s2 = "hsamsrv.dll" fullword ascii
		$s3 = "hZwOpenProcess" fullword ascii
		$s4 = "hOpenProcess" fullword ascii
		$s5 = ".?AVFeFinallyFailure@@" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}
