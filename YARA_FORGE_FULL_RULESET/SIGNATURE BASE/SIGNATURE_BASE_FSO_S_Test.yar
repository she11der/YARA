rule SIGNATURE_BASE_FSO_S_Test
{
	meta:
		description = "Webshells Auto-generated - file test.php"
		author = "Florian Roth (Nextron Systems)"
		id = "b0cc5a2a-c741-50dd-854f-5a43769e8f47"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L8325-L8337"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "82cf7b48da8286e644f575b039a99c26"
		logic_hash = "62613bead716717f116290b1c9eca9aa63eadd280050811e30a54e5d186af2fc"
		score = 50
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "$yazi = \"test\" . \"\\r\\n\";"
		$s2 = "fwrite ($fp, \"$yazi\");"

	condition:
		all of them
}
