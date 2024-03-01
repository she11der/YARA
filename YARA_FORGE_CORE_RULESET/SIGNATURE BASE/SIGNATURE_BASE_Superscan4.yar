import "pe"

rule SIGNATURE_BASE_Superscan4
{
	meta:
		description = "Auto-generated rule on file SuperScan4.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		id = "bd353382-ffa2-56c5-b842-1ffc94d6849e"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-hacktools.yar#L274-L287"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "78f76428ede30e555044b83c47bc86f0"
		logic_hash = "7f76c59e85efac5c150f783606e2a9bdc8724c6afd9f9c6405d63f7467c72752"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s2 = " td class=\"summO1\">"
		$s6 = "REM'EBAqRISE"
		$s7 = "CorExitProcess'msc#e"

	condition:
		all of them
}
