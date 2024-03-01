rule SIGNATURE_BASE_Trigger_Modify : FILE
{
	meta:
		description = "Chinese Hacktool Set - file trigger_modify.php"
		author = "Florian Roth (Nextron Systems)"
		id = "a7d65a9f-82de-554c-8f20-7560d2160041"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_webshells.yar#L86-L103"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "c93cd7a6c3f962381e9bf2b511db9b1639a22de0"
		logic_hash = "6ea0221af9e9a29d3280a01eec69e31e79c358e664d286f8c80259f5e826876c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<form name=\"form1\" method=\"post\" action=\"trigger_modify.php?trigger=<?php e" ascii
		$s2 = "$data_query = @mssql_query('sp_helptext \\'' . urldecode($_GET['trigger']) . '" ascii
		$s3 = "if($_POST['query'] != '')" fullword ascii
		$s4 = "$lines[] = 'I am unable to read this trigger.';" fullword ascii
		$s5 = "<b>Modify Trigger</b>" fullword ascii

	condition:
		filesize <15KB and all of them
}
