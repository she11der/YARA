rule SIGNATURE_BASE_Cgi_Python_Py
{
	meta:
		description = "Semi-Auto-generated  - file cgi-python.py.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "75e99d10-3cdf-5f87-9933-4ce5ebe18b09"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4729-L4741"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "0a15f473e2232b89dae1075e1afdac97"
		logic_hash = "37c6c7db32a52c8a83ff85f0a50c6fa71e833b9e6d20b1f95e9512fe8bbd0aee"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "a CGI by Fuzzyman"
		$s1 = "\"\"\"+fontline +\"Version : \" + versionstring + \"\"\", Running on : \"\"\" + "
		$s2 = "values = map(lambda x: x.value, theform[field])     # allows for"

	condition:
		1 of them
}