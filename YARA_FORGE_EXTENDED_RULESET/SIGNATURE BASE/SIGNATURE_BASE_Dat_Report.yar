rule SIGNATURE_BASE_Dat_Report : FILE
{
	meta:
		description = "Chinese Hacktool Set - file report.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "c77633a7-0c2f-5efa-b58b-635546bfec95"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L605-L619"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "4582a7c1d499bb96dad8e9b227e9d5de9becdfc2"
		logic_hash = "e3b21f37fae388958758af535727844d6e9696862fd9968340e1a619592c53b6"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<a href=\"http://www.xfocus.net\">X-Scan</a>" fullword ascii
		$s2 = "REPORT-ANALYSIS-OF-HOST" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <480KB and all of them
}
