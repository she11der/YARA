rule SIGNATURE_BASE_FSO_S_Phvayv
{
	meta:
		description = "Webshells Auto-generated - file phvayv.php"
		author = "Florian Roth (Nextron Systems)"
		id = "07e027a6-01a5-5250-a35e-fbfef1449cfe"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L7810-L7821"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "205ecda66c443083403efb1e5c7f7878"
		logic_hash = "d0482607f7d9cf6c89963cb9b1f943fa0b80636e857e0fb044cd9a0b3f974deb"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "wrap=\"OFF\">XXXX</textarea></font><font face"

	condition:
		all of them
}
