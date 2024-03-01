rule SIGNATURE_BASE_Webshell_Mysql_Interface_V1_0
{
	meta:
		description = "Web Shell - file Mysql interface v1.0.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L350-L363"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "a12fc0a3d31e2f89727b9678148cd487"
		logic_hash = "baa938c4cfd2c46b1752d866e186d76a04c353617d8ec3e0d78a3c546b120d13"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "echo \"<td><a href='$PHP_SELF?action=dropDB&dbname=$dbname' onClick=\\\"return"

	condition:
		all of them
}
