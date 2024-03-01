private rule SIGNATURE_BASE_Hatman_Origcode_PRIVATE : hatman
{
	meta:
		description = "No description has been set in the source file - Signature Base"
		author = "Florian Roth"
		id = "582b4cb6-54b5-5128-8c42-6759ec0f3976"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_hatman.yar#L58-L64"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "f6286e084bdbf3e2730a1aa3b7e302c1611c987447e083780e2d03000d1d226e"
		score = 75
		quality = 85
		tags = ""

	strings:
		$ocode_be = { 3c 00 00 03  60 00 a0 b0  7c 09 03 a6  4e 80 04 20 }
		$ocode_le = { 03 00 00 3c  b0 a0 00 60  a6 03 09 7c  20 04 80 4e }

	condition:
		$ocode_be or $ocode_le
}
