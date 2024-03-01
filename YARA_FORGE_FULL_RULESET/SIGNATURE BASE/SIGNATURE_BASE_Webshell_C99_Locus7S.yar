rule SIGNATURE_BASE_Webshell_C99_Locus7S
{
	meta:
		description = "PHP Webshells Github Archive - file c99_locus7s.php"
		author = "Florian Roth (Nextron Systems)"
		id = "f92fe5a2-e465-56ed-a77b-b32ea4c2c105"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L5976-L5991"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "d413d4700daed07561c9f95e1468fb80238fbf3c"
		logic_hash = "5ecfc5f6da471bd3037228c0bc762d50762933af3cf6674210c7b2017a45a646"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s8 = "$encoded = base64_encode(file_get_contents($d.$f)); " fullword
		$s9 = "$file = $tmpdir.\"dump_\".getenv(\"SERVER_NAME\").\"_\".$db.\"_\".date(\"d-m-Y"
		$s10 = "else {$tmp = htmlspecialchars(\"./dump_\".getenv(\"SERVER_NAME\").\"_\".$sq"
		$s11 = "$c99sh_sourcesurl = \"http://locus7s.com/\"; //Sources-server " fullword
		$s19 = "$nixpwdperpage = 100; // Get first N lines from /etc/passwd " fullword

	condition:
		2 of them
}
