rule SIGNATURE_BASE_Webshell_Dc3_Security_Crew_Shell_Priv_2
{
	meta:
		description = "PHP Webshells Github Archive - file dC3 Security Crew Shell PRiV.php"
		author = "Florian Roth (Nextron Systems)"
		id = "1d4a95c4-8128-504d-958f-dcc5c68f4975"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L6342-L6357"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "9077eb05f4ce19c31c93c2421430dd3068a37f17"
		logic_hash = "52dc0449c205ff9105e2dedc3cb4858f83a2efc7bae579656a26da493dc59500"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "@rmdir($_GET['file']) or die (\"[-]Error deleting dir!\");" fullword
		$s9 = "header(\"Last-Modified: \".date(\"r\",filemtime(__FILE__)));" fullword
		$s13 = "header(\"Content-type: image/gif\");" fullword
		$s14 = "@copy($file,$to) or die (\"[-]Error copying file!\");" fullword
		$s20 = "if (isset($_GET['rename_all'])) {" fullword

	condition:
		3 of them
}
