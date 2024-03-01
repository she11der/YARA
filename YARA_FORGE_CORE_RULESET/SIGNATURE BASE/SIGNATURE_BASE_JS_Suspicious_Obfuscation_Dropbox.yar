rule SIGNATURE_BASE_JS_Suspicious_Obfuscation_Dropbox
{
	meta:
		description = "Detects PowerShell AMSI Bypass"
		author = "Florian Roth (Nextron Systems)"
		id = "9b6b288d-3a15-5267-bbb1-885febf4df78"
		date = "2017-07-19"
		modified = "2023-12-05"
		reference = "https://twitter.com/ItsReallyNick/status/887705105239343104"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_mal_scripts.yar#L19-L33"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "19d1dd25c4a5e18dca131709a64c3537278754ec9d67b0bb49bde9b1493d3dc7"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "j\"+\"a\"+\"v\"+\"a\"+\"s\"+\"c\"+\"r\"+\"i\"+\"p\"+\"t\""
		$x2 = "script:https://www.dropbox.com" ascii

	condition:
		2 of them
}
