rule SIGNATURE_BASE_Webshell_Php
{
	meta:
		description = "Semi-Auto-generated  - file webshell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L4278-L4289"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "e425241b928e992bde43dd65180a4894"
		logic_hash = "7b0f4f4afde7dcb44c9d877a72c961f3666278ce28a24ae8068cfbc32639e307"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s2 = "<die(\"Couldn't Read directory, Blocked!!!\");"
		$s3 = "PHP Web Shell"

	condition:
		all of them
}
