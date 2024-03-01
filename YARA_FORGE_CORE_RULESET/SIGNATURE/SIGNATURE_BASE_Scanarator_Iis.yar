import "pe"

rule SIGNATURE_BASE_Scanarator_Iis
{
	meta:
		description = "Auto-generated rule on file iis.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		id = "a467147b-53c8-53db-aa33-5f0e4e066988"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-hacktools.yar#L422-L433"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "3a8fc02c62c8dd65e038cc03e5451b6e"
		logic_hash = "092cb902e10624b207b7932e6b3c1fe2277ed1d183e5de9ee4d07d8548e90ab6"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "example: iis 10.10.10.10"
		$s1 = "send error"

	condition:
		all of them
}
