rule SIGNATURE_BASE_Webshell_NCC_Shell
{
	meta:
		description = "PHP Webshells Github Archive - file NCC-Shell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "3a2dab3d-faf0-52a5-b114-db402885c618"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L6205-L6221"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "64d4495875a809b2730bd93bec2e33902ea80a53"
		logic_hash = "c58edc548b7804be25f6956e9407cc9f8c74dfd8651f601a87ba639284e612d9"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = " if (isset($_FILES['probe']) and ! $_FILES['probe']['error']) {" fullword
		$s1 = "<b>--Coded by Silver" fullword
		$s2 = "<title>Upload - Shell/Datei</title>" fullword
		$s8 = "<a href=\"http://www.n-c-c.6x.to\" target=\"_blank\">-->NCC<--</a></center></b><"
		$s14 = "~|_Team .:National Cracker Crew:._|~<br>" fullword
		$s18 = "printf(\"Sie ist %u Bytes gro" fullword

	condition:
		3 of them
}
