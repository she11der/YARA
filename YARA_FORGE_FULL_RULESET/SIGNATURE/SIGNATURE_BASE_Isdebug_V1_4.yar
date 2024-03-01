rule SIGNATURE_BASE_Isdebug_V1_4 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file IsDebug V1.4.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "f9b4a909-e0e5-5708-8794-39250b9d56cc"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L990-L1010"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "ca32474c358b4402421ece1cb31714fbb088b69a"
		logic_hash = "d656327c33533b5ef7dc70ec00250ee35d878794fae189829a0ecad958f96616"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "IsDebug.dll" fullword ascii
		$s1 = "SV Dumper V1.0" fullword wide
		$s2 = "(IsDebuggerPresent byte Patcher)" fullword ascii
		$s8 = "Error WriteMemory failed" fullword ascii
		$s9 = "IsDebugPresent" fullword ascii
		$s10 = "idb_Autoload" fullword ascii
		$s11 = "Bin Files" fullword ascii
		$s12 = "MASM32 version" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <30KB and all of them
}
