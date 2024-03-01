rule SIGNATURE_BASE_RAT_Darkrat
{
	meta:
		description = "Detects DarkRAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "8283236a-6ed1-5213-8386-a029867b9677"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/DarkRAT"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_rats_malwareconfig.yar#L284-L306"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "dccb473a3cf4478dd1dbf8b35ad564f59740676ecde90266a0dc15cbad89bfe7"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "@1906dark1996coder@"
		$b = "SHEmptyRecycleBinA"
		$c = "mciSendStringA"
		$d = "add_Shutdown"
		$e = "get_SaveMySettingsOnExit"
		$f = "get_SpecialDirectories"
		$g = "Client.My"

	condition:
		all of them
}
