rule SIGNATURE_BASE_Webshell_Webshells_New_Make2
{
	meta:
		description = "Web shells - generated from file make2.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-03-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L3220-L3233"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "9af195491101e0816a263c106e4c145e"
		logic_hash = "7c94c925b5fd7fbc37428c21a9ea3c5a73f4fa0a20a1f5d03f0d5a990bd6f45a"
		score = 50
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "error_reporting(0);session_start();header(\"Content-type:text/html;charset=utf-8"

	condition:
		all of them
}
