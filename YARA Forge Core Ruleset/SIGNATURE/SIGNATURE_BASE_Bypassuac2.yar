rule SIGNATURE_BASE_Bypassuac2
{
	meta:
		description = "Auto-generated rule - file BypassUac2.zip"
		author = "yarGen Yara Rule Generator"
		id = "8b7e49de-9b0a-5dc4-86af-1a854dc649cc"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-hacktools.yar#L955-L967"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "ef3e7dd2d1384ecec1a37254303959a43695df61"
		logic_hash = "398783fa0453a60fd1c6aa64eacfbfa7c5385e81c79d1b6a8a8386dae9b825cc"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "/BypassUac/BypassUac/BypassUac_Utils.cpp" fullword ascii
		$s1 = "/BypassUac/BypassUacDll/BypassUacDll.aps" fullword ascii
		$s3 = "/BypassUac/BypassUac/BypassUac.ico" fullword ascii

	condition:
		all of them
}