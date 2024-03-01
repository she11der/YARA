rule SIGNATURE_BASE_Dllinjection
{
	meta:
		description = "Webshells Auto-generated - file DllInjection.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "8a57e122-fd00-57f3-94db-736c5bfd76db"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L7623-L7634"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "a7b92283a5102886ab8aee2bc5c8d718"
		logic_hash = "6e01ae1cc8a91a5e0d22bdf477aa72bf0116dbe31752a069b1e34d8a09ec6213"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "\\BDoor\\DllInjecti"

	condition:
		all of them
}
