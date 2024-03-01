rule SIGNATURE_BASE_Webshell_Phpkit_0_1A_Odd
{
	meta:
		description = "Web Shell - file odd.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L1099-L1115"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "3c30399e7480c09276f412271f60ed01"
		logic_hash = "745734658ed4000e1399531ae44125f8462ecd37388e6223cfa9bf91dbb52bbc"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "include('php://input');" fullword
		$s3 = "ini_set('allow_url_include, 1'); // Allow url inclusion in this script" fullword
		$s4 = "// uses include('php://input') to execute arbritary code" fullword
		$s5 = "// php://input based backdoor" fullword

	condition:
		2 of them
}
