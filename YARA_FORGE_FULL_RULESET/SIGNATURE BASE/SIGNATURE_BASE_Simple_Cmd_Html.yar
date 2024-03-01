rule SIGNATURE_BASE_Simple_Cmd_Html
{
	meta:
		description = "Semi-Auto-generated  - file simple_cmd.html.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "30990574-02a0-5eed-8317-847b6be13300"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L4942-L4955"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "c6381412df74dbf3bcd5a2b31522b544"
		logic_hash = "56b5b9e5518fa8a4be8c48735e997a538b0e534ad8fd72c1419dc0e8353bbc00"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "<title>G-Security Webshell</title>" fullword
		$s2 = "<input type=TEXT name=\"-cmd\" size=64 value=\"<?=$cmd?>\" " fullword
		$s3 = "<? if($cmd != \"\") print Shell_Exec($cmd);?>" fullword
		$s4 = "<? $cmd = $_REQUEST[\"-cmd\"];?>" fullword

	condition:
		all of them
}
