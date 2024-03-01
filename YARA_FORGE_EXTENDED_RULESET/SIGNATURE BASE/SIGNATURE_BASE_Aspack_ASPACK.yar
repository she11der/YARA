import "pe"

rule SIGNATURE_BASE_Aspack_ASPACK
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file ASPACK.EXE"
		author = "Florian Roth (Nextron Systems)"
		id = "ca9a25f9-a94b-5e10-b935-c6e2d38d999c"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L2163-L2178"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "c589e6fd48cfca99d6335e720f516e163f6f3f42"
		logic_hash = "1c7abc0a126ee8c8b20e55ad85974067f1a230efc5f95a1a1e732025e39d5bab"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "ASPACK.EXE" fullword wide
		$s5 = "CLOSEDFOLDER" fullword wide
		$s10 = "ASPack compressor" fullword wide

	condition:
		all of them
}
