rule SIGNATURE_BASE_EXPL_Manageengine_CVE_2022_47966_Jan23_1
{
	meta:
		description = "Detects indicators of exploitation of ManageEngine vulnerability as described by Horizon3"
		author = "Florian Roth (Nextron Systems)"
		id = "07535b9c-8611-5a46-bcd7-f94070de2aea"
		date = "2023-01-13"
		modified = "2023-12-05"
		reference = "https://www.horizon3.ai/manageengine-cve-2022-47966-iocs/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/expl_manageengine_jan23.yar#L2-L14"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "a62064e4f12632ba6c14cbbd9369ee919536334f19021a177c126b5dff7e568c"
		score = 75
		quality = 85
		tags = ""

	strings:
		$ = "]: com.adventnet.authentication.saml.SamlException: Signature validation failed. SAML Response rejected|"

	condition:
		1 of them
}
