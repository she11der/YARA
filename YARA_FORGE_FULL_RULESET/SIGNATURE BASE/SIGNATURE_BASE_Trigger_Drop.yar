rule SIGNATURE_BASE_Trigger_Drop : FILE
{
	meta:
		description = "Chinese Hacktool Set - file trigger_drop.php"
		author = "Florian Roth (Nextron Systems)"
		id = "3b4f32ff-2de2-5689-869a-8a8f55e7fa0c"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_webshells.yar#L35-L51"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "165dd2d82bf87285c8a53ad1ede6d61a90837ba4"
		logic_hash = "fc998ea5c2a446278823e4336ddc6a22741f82c43fbdcd95b3d12ee6a27b1dd7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "$_GET['returnto'] = 'database_properties.php';" fullword ascii
		$s1 = "echo('<meta http-equiv=\"refresh\" content=\"0;url=' . $_GET['returnto'] . '\">'" ascii
		$s2 = "@mssql_query('DROP TRIGGER" ascii
		$s3 = "if(empty($_GET['returnto']))" fullword ascii

	condition:
		filesize <5KB and all of them
}
