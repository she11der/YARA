rule SIGNATURE_BASE_CN_Honker_Termsrvhack : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file termsrvhack.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "4fd582a1-3c6d-57a1-bba0-f775bb61ef00"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L756-L771"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "1c456520a7b7faf71900c71167038185f5a7d312"
		logic_hash = "ef0b9965e2d419230a7a8425674edb356347d1e41538d19fc67f8b0fbc69091f"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "The terminal server cannot issue a client license.  It was unable to issue the" wide
		$s6 = "%s\\%s\\%d\\%d" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <1052KB and all of them
}
