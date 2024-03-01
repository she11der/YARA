rule SIGNATURE_BASE_Webshell_Phpspy_Ver_2006
{
	meta:
		description = "PHP Webshells Github Archive - file PhpSpy Ver 2006.php"
		author = "Florian Roth (Nextron Systems)"
		id = "adbb1963-31c8-5540-a679-c75b1101c163"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L6557-L6571"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "34a89e0ab896c3518d9a474b71ee636ca595625d"
		logic_hash = "69bd2c387b0e676168116f3b3c3c081e08fd555cc6bc9a94b9c8ef97f194b09f"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "var_dump(@$shell->RegRead($_POST['readregname']));" fullword
		$s12 = "$prog = isset($_POST['prog']) ? $_POST['prog'] : \"/c net start > \".$pathname."
		$s19 = "$program = isset($_POST['program']) ? $_POST['program'] : \"c:\\winnt\\system32"
		$s20 = "$regval = isset($_POST['regval']) ? $_POST['regval'] : 'c:\\winnt\\backdoor.exe'"

	condition:
		1 of them
}
