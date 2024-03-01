rule SIGNATURE_BASE_Reader_Asp
{
	meta:
		description = "Semi-Auto-generated  - file Reader.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "70094d24-fa3a-503c-b9b6-294a883fc52c"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L4212-L4224"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "ad1a362e0a24c4475335e3e891a01731"
		logic_hash = "ec0dc3b050d84e852e0c18bd00961f109d3506fa7f2e8656448bd5edd28d9305"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "Mehdi & HolyDemon"
		$s2 = "www.infilak."
		$s3 = "'*T@*r@#@&mms^PdbYbVuBcAAA==^#~@%><form method=post name=inf><table width=\"75%"

	condition:
		2 of them
}
