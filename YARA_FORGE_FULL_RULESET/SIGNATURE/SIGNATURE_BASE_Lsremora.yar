import "pe"

rule SIGNATURE_BASE_Lsremora : FILE
{
	meta:
		description = "Detects a tool used by APT groups"
		author = "Florian Roth (Nextron Systems)"
		id = "c15c583f-70cd-5a80-bdea-a14582097e50"
		date = "2016-09-08"
		modified = "2023-12-05"
		reference = "http://goo.gl/igxLyF"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L3301-L3323"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ac8f6b7284307456749b3386340a2b3deb0718bc68875bc90bccf74a96469a59"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "efa66f6391ec471ca52cd053159c8a8778f11f921da14e6daf76387f8c9afcd5"
		hash2 = "e0327c1218fd3723e20acc780e20135f41abca35c35e0f97f7eccac265f4f44e"

	strings:
		$x1 = "Target: Failed to load primary SAM functions." fullword ascii
		$x2 = "lsremora64.dll" fullword ascii
		$x3 = "PwDumpError:999999" fullword wide
		$x4 = "PwDumpError" fullword wide
		$x5 = "lsremora.dll" fullword ascii
		$s1 = ":\\\\.\\pipe\\%s" fullword ascii
		$s2 = "x%s_history_%d:%d" fullword wide
		$s3 = "Using pipe %s" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 1 of ($x*)) or (3 of them )
}
