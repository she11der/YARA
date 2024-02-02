rule SIGNATURE_BASE_MAL_JS_Efile_Apr23_1
{
	meta:
		description = "Detects JavaScript malware used in eFile compromise"
		author = "Florian Roth"
		id = "ba7a8b2c-789c-5bc5-be53-f2b92c7039e1"
		date = "2023-04-06"
		modified = "2023-12-05"
		reference = "https://twitter.com/Ax_Sharma/status/1643178696084271104/photo/1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/mal_efile_apr23.yar#L2-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "6d94162e5719b92d9df349e7d48cd70e218998b0e120870a435a8073fa49c532"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "let payload_chrome = "
		$s2 = "else if (agent.indexOf(\"firefox"

	condition:
		all of them
}