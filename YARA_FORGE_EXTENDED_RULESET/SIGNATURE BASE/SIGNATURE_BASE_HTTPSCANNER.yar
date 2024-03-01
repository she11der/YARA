rule SIGNATURE_BASE_HTTPSCANNER : FILE
{
	meta:
		description = "Chinese Hacktool Set - file HTTPSCANNER.EXE"
		author = "Florian Roth (Nextron Systems)"
		id = "470c90f5-bb98-59ab-bff4-f6238c318e36"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1012-L1026"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "ae2929346944c1ea3411a4562e9d5e2f765d088a"
		logic_hash = "0f1460101198d8b139b7cc0674bef2fc7b3d2a24249f521396b7bbe4318a83d5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "HttpScanner.exe" fullword wide
		$s2 = "HttpScanner" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <3500KB and all of them
}
