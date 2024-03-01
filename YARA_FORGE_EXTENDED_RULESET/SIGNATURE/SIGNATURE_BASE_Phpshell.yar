rule SIGNATURE_BASE_Phpshell
{
	meta:
		description = "Webshells Auto-generated - file PhpShell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "887264d3-5704-5e38-b0a6-44d529258ea2"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L7263-L7274"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "539baa0d39a9cf3c64d65ee7a8738620"
		logic_hash = "95b3cedac370bf9b06092035a738722f3ec97e6cbafe3d4f742429a865576ad8"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "href=\"http://www.gimpster.com/wiki/PhpShell\">www.gimpster.com/wiki/PhpShell</a>."

	condition:
		all of them
}
