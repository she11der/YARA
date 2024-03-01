rule SIGNATURE_BASE_Simple_PHP_Backdoor
{
	meta:
		description = "Webshells Auto-generated - file Simple_PHP_BackDooR.php"
		author = "Florian Roth (Nextron Systems)"
		id = "bd7c19b9-e035-5e70-b626-1d210cadc055"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L7594-L7607"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "a401132363eecc3a1040774bec9cb24f"
		logic_hash = "9739217c23f583452fbf1d7a8e20b2f1379ebf430e0a4fd73ad62e88d544670a"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<hr>to browse go to http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=[directory he"
		$s6 = "if(!move_uploaded_file($HTTP_POST_FILES['file_name']['tmp_name'], $dir.$fn"
		$s9 = "// a simple php backdoor"

	condition:
		1 of them
}
