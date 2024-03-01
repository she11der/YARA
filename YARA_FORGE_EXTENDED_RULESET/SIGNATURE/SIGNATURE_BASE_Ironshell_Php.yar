rule SIGNATURE_BASE_Ironshell_Php
{
	meta:
		description = "Semi-Auto-generated  - file ironshell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "0d63ad03-4d1d-535f-8afe-3edaf1bf4010"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L4834-L4848"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "8bfa2eeb8a3ff6afc619258e39fded56"
		logic_hash = "23574299ee2bb33c3f71102adf71ac8f09b6f8ece5f798beacb9b2432d297ee7"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "www.ironwarez.info"
		$s1 = "$cookiename = \"wieeeee\";"
		$s2 = "~ Shell I"
		$s3 = "www.rootshell-team.info"
		$s4 = "setcookie($cookiename, $_POST['pass'], time()+3600);"

	condition:
		1 of them
}
