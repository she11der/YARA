rule SIGNATURE_BASE_Settings : FILE
{
	meta:
		description = "Laudanum Injector Tools - file settings.php"
		author = "Florian Roth (Nextron Systems)"
		id = "054b8723-fdfa-51dc-91ae-b915e40b2e54"
		date = "2015-06-22"
		modified = "2023-12-05"
		reference = "http://laudanum.inguardians.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_laudanum_webshells.yar#L68-L83"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "588739b9e4ef2dbb0b4cf630b73295d8134cc801"
		logic_hash = "b02e293e659fa77257d0642c57e51d6ae712d9221ae295cf69bb845f68c650ee"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Port: <input name=\"port\" type=\"text\" value=\"8888\">" fullword ascii
		$s2 = "<li>Reverse Shell - " fullword ascii
		$s3 = "<li><a href=\"<?php echo plugins_url('file.php', __FILE__);?>\">File Browser</a>" ascii

	condition:
		filesize <13KB and all of them
}
