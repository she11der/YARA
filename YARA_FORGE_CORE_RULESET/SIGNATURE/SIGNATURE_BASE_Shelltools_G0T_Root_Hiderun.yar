rule SIGNATURE_BASE_Shelltools_G0T_Root_Hiderun
{
	meta:
		description = "Webshells Auto-generated - file HideRun.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "dd71dbef-5b5d-5976-8b95-0f202a4b4795"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8598-L8610"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "45436d9bfd8ff94b71eeaeb280025afe"
		logic_hash = "3a6dea2314800b28e92b59595c8b79c64e66dc66ebfa8f89c2f4028b574b9a91"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Usage -- hiderun [AppName]"
		$s7 = "PVAX SW, Alexey A. Popoff, Moscow, 1997."

	condition:
		all of them
}
