rule SIGNATURE_BASE_Sqlcracker : FILE
{
	meta:
		description = "Chinese Hacktool Set - file SQLCracker.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "7d7ff2cf-81fb-5a04-a97f-577c306137a9"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L673-L690"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "1aa5755da1a9b050c4c49fc5c58fa133b8380410"
		logic_hash = "3724f4b746da413f99880564ae72bc0de867120f1f7eacaf856d42492ebe359e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "msvbvm60.dll" fullword ascii
		$s1 = "_CIcos" fullword ascii
		$s2 = "kernel32.dll" fullword ascii
		$s3 = "cKmhV" fullword ascii
		$s4 = "080404B0" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <125KB and all of them
}
