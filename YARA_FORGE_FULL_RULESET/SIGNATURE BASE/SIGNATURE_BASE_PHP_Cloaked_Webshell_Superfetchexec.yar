rule SIGNATURE_BASE_PHP_Cloaked_Webshell_Superfetchexec
{
	meta:
		description = "Looks like a webshell cloaked as GIF - http://goo.gl/xFvioC"
		author = "Florian Roth (Nextron Systems)"
		id = "4611129a-9865-5603-b1ec-7db0058a80d7"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "http://goo.gl/xFvioC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L5539-L5551"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "320b85b1ad39a90578f53c69838b6264af1e6a71c509aefc0986c7f0c77fdae9"
		score = 50
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "else{$d.=@chr(($h[$e[$o]]<<4)+($h[$e[++$o]]));}}eval($d);"

	condition:
		$s0
}
