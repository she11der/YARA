rule SIGNATURE_BASE_Webshell_Caidao_Shell_Ice_2
{
	meta:
		description = "Web Shell - file ice.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L449-L462"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "1d6335247f58e0a5b03e17977888f5f2"
		logic_hash = "57c3c369abd826d676290300d8df2d890b777fa1f0e1156654062159a4228db7"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<?php ${${eval($_POST[ice])}};?>" fullword

	condition:
		all of them
}
