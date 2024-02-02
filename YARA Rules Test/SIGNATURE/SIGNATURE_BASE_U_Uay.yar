rule SIGNATURE_BASE_U_Uay
{
	meta:
		description = "Webshells Auto-generated - file uay.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "6a670e19-6e53-5b13-aabf-fe74d48b9113"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8806-L8818"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "abbc7b31a24475e4c5d82fc4c2b8c7c4"
		logic_hash = "45e8938ce34fd5a253cee3867aa8c4429c6bf3fcc91098ed9df3f95656bc5f8f"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "exec \"c:\\WINDOWS\\System32\\freecell.exe"
		$s9 = "SYSTEM\\CurrentControlSet\\Services\\uay.sys\\Security"

	condition:
		1 of them
}