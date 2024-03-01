import "pe"

rule SIGNATURE_BASE_Hacktools_CN_445_Cmd : FILE
{
	meta:
		description = "Disclosed hacktool set - file cmd.bat"
		author = "Florian Roth (Nextron Systems)"
		id = "b9693f51-26ac-5bf1-8c4d-ca852a154636"
		date = "2014-11-17"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L1231-L1246"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "69b105a3aec3234819868c1a913772c40c6b727a"
		logic_hash = "e0ab572fe9009ddc39f34302d8a16531c23f51ce4ea373d57a039f22ccc934c7"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$bat = "@echo off" fullword ascii
		$s0 = "cs.exe %1" fullword ascii
		$s2 = "nc %1 4444" fullword ascii

	condition:
		uint32(0)==0x68636540 and $bat at 0 and all of ($s*)
}
