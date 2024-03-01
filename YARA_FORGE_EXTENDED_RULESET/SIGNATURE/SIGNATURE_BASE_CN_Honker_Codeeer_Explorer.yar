rule SIGNATURE_BASE_CN_Honker_Codeeer_Explorer : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Codeeer Explorer.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "d4a88ae7-c0b2-57d2-a070-3dd748a30a3a"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L542-L557"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "f32e05f3fefbaa2791dd750e4a3812581ce0f205"
		logic_hash = "299d0181beb5032dcb327516a7526d6131e2212623ffa9e592f54f80473b098d"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "Codeeer Explorer.exe" fullword wide
		$s12 = "webBrowser1_ProgressChanged" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <470KB and all of them
}
