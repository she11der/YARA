import "pe"

rule SIGNATURE_BASE_Splitjoin
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file splitjoin.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "2f1a69cd-34b3-5af0-a054-fe19d9becb25"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L1879-L1895"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "e4a9ef5d417038c4c76b72b5a636769a98bd2f8c"
		logic_hash = "dede4518ed9be28e89bc67dab4e68503383c16746f088f37a4c8069e256183ca"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Not for distribution without the authors permission" fullword wide
		$s2 = "Utility to split and rejoin files.0" fullword wide
		$s5 = "Copyright (c) Angus Johnson 2001-2002" fullword wide
		$s19 = "SplitJoin" fullword wide

	condition:
		all of them
}
