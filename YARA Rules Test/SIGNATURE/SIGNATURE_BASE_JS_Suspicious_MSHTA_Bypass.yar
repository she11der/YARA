rule SIGNATURE_BASE_JS_Suspicious_MSHTA_Bypass
{
	meta:
		description = "Detects MSHTA Bypass"
		author = "Florian Roth (Nextron Systems)"
		id = "b2ddca78-c19a-5bb6-a1c9-4413e637ab1d"
		date = "2017-07-19"
		modified = "2023-12-05"
		reference = "https://twitter.com/ItsReallyNick/status/887705105239343104"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_mal_scripts.yar#L35-L50"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "df68cac0da19c5705353f26fc3f2a99556b7230f9d4f52e7a2e35cb48997b699"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "mshtml,RunHTMLApplication" ascii
		$s2 = "new ActiveXObject(\"WScript.Shell\").Run(" ascii
		$s3 = "/c start mshta j" ascii nocase

	condition:
		2 of them
}