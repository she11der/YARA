rule SIGNATURE_BASE_Rtf_Cve2017_11882_Ole : malicious exploit cve_2017_11882
{
	meta:
		description = "Attempts to identify the exploit CVE 2017 11882"
		author = "John Davison"
		id = "b6c59cf1-52e4-5c9e-b3c3-d973d52736e3"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://embedi.com/blog/skeleton-closet-ms-office-vulnerability-you-didnt-know-about"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/exploit_cve_2017_11882.yar#L1-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "51cf2a6c0c1a29abca9fd13cb22421da"
		logic_hash = "6856d3c78cc06899d2bc1f876dce6b718513ebad80f37d7b5914a14d1da5064c"
		score = 60
		quality = 85
		tags = ""

	strings:
		$headers = { 1c 00 00 00 02 00 ?? ?? a9 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 03 01 01 03 ?? }
		$font = { 0a 01 08 5a 5a }
		$winexec = { 12 0c 43 00 }

	condition:
		all of them and @font>@headers and @winexec==@font+5+44
}
