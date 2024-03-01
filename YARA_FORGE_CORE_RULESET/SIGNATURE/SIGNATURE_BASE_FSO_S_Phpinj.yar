rule SIGNATURE_BASE_FSO_S_Phpinj
{
	meta:
		description = "Webshells Auto-generated - file phpinj.php"
		author = "Florian Roth (Nextron Systems)"
		id = "5d84d518-0e18-517f-890b-e296ac265c50"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8455-L8466"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "dd39d17e9baca0363cc1c3664e608929"
		logic_hash = "de4ac200f5426ec4c6fef21d5fbc37281811569a3e71a9bcb6fa51d13eb600a4"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s4 = "echo '<a href='.$expurl.'> Click Here to Exploit </a> <br />';"

	condition:
		all of them
}
