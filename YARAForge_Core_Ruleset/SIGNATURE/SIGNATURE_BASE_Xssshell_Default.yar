rule SIGNATURE_BASE_Xssshell_Default
{
	meta:
		description = "Webshells Auto-generated - file default.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "1c221572-4cb5-5806-a856-0f857dba230a"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8491-L8502"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "d156782ae5e0b3724de3227b42fcaf2f"
		logic_hash = "6a8772a8a6399c3266abcc22a3c55eda70ec9703346398f5f1768bbd35974f8c"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s3 = "If ProxyData <> \"\" Then ProxyData = Replace(ProxyData, DATA_SEPERATOR, \"<br />\")"

	condition:
		all of them
}