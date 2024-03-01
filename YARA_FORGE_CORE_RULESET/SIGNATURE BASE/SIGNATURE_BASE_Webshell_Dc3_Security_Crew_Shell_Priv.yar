rule SIGNATURE_BASE_Webshell_Dc3_Security_Crew_Shell_Priv
{
	meta:
		description = "PHP Webshells Github Archive - file dC3_Security_Crew_Shell_PRiV.php"
		author = "Florian Roth (Nextron Systems)"
		id = "c83bb4ba-6b4e-5a88-925b-b93d08b304e4"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L5571-L5587"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "1b2a4a7174ca170b4e3a8cdf4814c92695134c8a"
		logic_hash = "f93a5d87d4a490844de578067dc0b7bac6b01ceb9130cd7c70a227566e18f16c"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "@rmdir($_GET['file']) or die (\"[-]Error deleting dir!\");" fullword
		$s4 = "$ps=str_replace(\"\\\\\",\"/\",getenv('DOCUMENT_ROOT'));" fullword
		$s5 = "header(\"Expires: \".date(\"r\",mktime(0,0,0,1,1,2030)));" fullword
		$s15 = "search_file($_POST['search'],urldecode($_POST['dir']));" fullword
		$s16 = "echo base64_decode($images[$_GET['pic']]);" fullword
		$s20 = "if (isset($_GET['rename_all'])) {" fullword

	condition:
		3 of them
}
