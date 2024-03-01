import "pe"

rule SIGNATURE_BASE_SUSP_APT_MAL_VEILEDSIGNAL_Backdoor_Apr23
{
	meta:
		description = "Detects marker found in VEILEDSIGNAL backdoor"
		author = "X__Junior"
		id = "8f0d92b6-d9b0-55e3-b2ca-601d095f5279"
		date = "2023-04-20"
		modified = "2023-04-21"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_nk_tradingtech_apr23.yar#L19-L35"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "ccb482a7634dc24fde03b5730bf28a9e028f8d5a9ad46ba9663d1b520264d8f4"
		score = 75
		quality = 85
		tags = ""
		hash1 = "aa318070ad1bf90ed459ac34dc5254acc178baff3202d2ea7f49aaf5a055dd43"

	strings:
		$opb1 = { 81 BD ?? ?? ?? ?? 5E DA F3 76}
		$opb2 = { C7 85 ?? ?? ?? ?? 74 F2 39 DA 66 C7 85 ?? ?? ?? ?? E5 CF}
		$opb3 = { C7 85 ?? ?? ?? ?? 74 F2 39 DA B9 00 04 00 00 66 C7 85 ?? ?? ?? ?? E5 CF }

	condition:
		2 of them
}
