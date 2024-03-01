rule SIGNATURE_BASE_CN_Tools_Srss_2 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file srss.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "3a84fa58-ccd0-5cf0-b1e0-a8f2ca04fd3f"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1834-L1856"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "c418b30d004051bbf1b2d3be426936b95b5fea6f"
		logic_hash = "e674ac7a99a67e2ebe8b4c4232e3435dd041b794f6c08a87ef7b8179127d6fc7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "used pepack!" fullword ascii
		$s1 = "KERNEL32.dll" fullword ascii
		$s2 = "KERNEL32.DLL" fullword ascii
		$s3 = "LoadLibraryA" fullword ascii
		$s4 = "GetProcAddress" fullword ascii
		$s5 = "VirtualProtect" fullword ascii
		$s6 = "VirtualAlloc" fullword ascii
		$s7 = "VirtualFree" fullword ascii
		$s8 = "ExitProcess" fullword ascii

	condition:
		uint16(0)==0x5a4d and ($x1 at 0) and filesize <14KB and all of ($s*)
}
