import "pe"

rule SIGNATURE_BASE_HKTL_Moorer_Port_Scanner
{
	meta:
		description = "Auto-generated rule on file MooreR Port Scanner.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		id = "5d8fb83f-bed3-53d2-bd33-2158911dc7c8"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-hacktools.yar#L204-L217"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "376304acdd0b0251c8b19fea20bb6f5b"
		logic_hash = "248f437964fc6f7836f6b4c87e1f35bb1bac25a1a484cdf1a4065e7efb823b51"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "Description|"
		$s3 = "soft Visual Studio\\VB9yp"
		$s4 = "adj_fptan?4"
		$s7 = "DOWS\\SyMem32\\/o"

	condition:
		all of them
}
