rule SIGNATURE_BASE_Wiltedtulip_Powershell
{
	meta:
		description = "Detects powershell script used in Operation Wilted Tulip"
		author = "Florian Roth (Nextron Systems)"
		id = "b6246508-a6ff-5a02-a0de-9cde139f0acc"
		date = "2017-07-23"
		modified = "2023-12-05"
		reference = "http://www.clearskysec.com/tulip"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_wilted_tulip.yar#L47-L60"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "57d28f7b79cc14b8bbc2d7c9b2c16ab0f94a4b160cf7cb1d4641fe1c77e06811"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "e5ee1f45cbfdb54b02180e158c3c1f080d89bce6a7d1fe99dd0ff09d47a36787"

	strings:
		$x1 = "powershell.exe -nop -w hidden -c if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:windir+" ascii

	condition:
		1 of them
}