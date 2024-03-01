rule SIGNATURE_BASE__W_Php_Php_Wacking_Php_Php_Specialshell_99_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, wacking.php.php.txt, SpecialShell_99.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "c01ad0e5-1aff-5128-9d0c-5d0967532a4b"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L5107-L5121"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "7bdaebfb093b58a2fd33b4bbeea8465d0f724383b4855eb521a3e339ee153781"
		score = 75
		quality = 85
		tags = ""
		super_rule = 1
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "9c5bb5e3a46ec28039e8986324e42792"
		hash2 = "09609851caa129e40b0d56e90dfc476c"

	strings:
		$s0 = "\"<td>&nbsp;<a href=\\\"\".$sql_surl.\"sql_act=query&sql_query=\".ur"
		$s2 = "c99sh_sqlquery"

	condition:
		1 of them
}
