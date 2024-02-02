rule SIGNATURE_BASE_NT_Addy_Asp
{
	meta:
		description = "Semi-Auto-generated  - file NT Addy.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "18f5f360-8690-5e09-ac18-b8cc4f678811"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L3779-L3791"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "2e0d1bae844c9a8e6e351297d77a1fec"
		logic_hash = "0fc61d5e276786b8be822712cdcfc81146998e535532e44d3da92e0668713a48"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "NTDaddy v1.9 by obzerve of fux0r inc"
		$s2 = "<ERROR: THIS IS NOT A TEXT FILE>"
		$s4 = "RAW D.O.S. COMMAND INTERFACE"

	condition:
		1 of them
}