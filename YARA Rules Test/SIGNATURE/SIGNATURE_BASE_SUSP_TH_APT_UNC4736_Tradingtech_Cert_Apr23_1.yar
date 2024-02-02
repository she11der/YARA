rule SIGNATURE_BASE_SUSP_TH_APT_UNC4736_Tradingtech_Cert_Apr23_1
{
	meta:
		description = "Threat hunting rule that detects samples signed with the compromised Trading Technologies certificate after May 2022"
		author = "Florian Roth"
		id = "9a05fba9-9466-5b69-9207-27ad01d6eb8b"
		date = "2023-04-20"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_nk_tradingtech_apr23.yar#L227-L242"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "47941828b3c18ed39eddacbc73e147651a9bd48e1a0f7b9847ff1d4c6fea6afd"
		score = 65
		quality = 85
		tags = ""

	strings:
		$s1 = { 00 85 38 A6 C5 01 8F 50 FC }
		$s2 = "Go Daddy Secure Certificate Authority - G2"
		$s3 = "Trading Technologies International, Inc"

	condition:
		pe.timestamp>1651363200 and all of them
}