rule SIGNATURE_BASE_Felikspack3___PHP_Shells_Xishell
{
	meta:
		description = "Webshells Auto-generated - file xIShell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "32a32a9a-8d5f-5b3f-8ff4-560555f0ae1e"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L8407-L8418"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "997c8437c0621b4b753a546a53a88674"
		logic_hash = "13393bc72477ab9a4ebc16b409de8ed73e086cc41f25f34315d11401b63c2471"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s3 = "if (!$nix) { $xid = implode(explode(\"\\\\\",$xid),\"\\\\\\\\\");}echo (\"<td><a href='Java"

	condition:
		all of them
}
