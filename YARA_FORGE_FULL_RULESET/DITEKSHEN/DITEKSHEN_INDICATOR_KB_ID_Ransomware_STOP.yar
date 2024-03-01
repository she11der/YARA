rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_STOP
{
	meta:
		description = "Detects files referencing identities associated with STOP ransomware"
		author = "ditekShen"
		id = "b2279a7f-a187-5a44-bf1f-87c21b3ffa4f"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_id.yar#L464-L480"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "f0d902edbcbe8ff8f3a751b649554499933b06471920c86a9eea3de23890b4bc"
		score = 75
		quality = 57
		tags = ""

	strings:
		$s1 = "gorentos@bitmessage.ch" ascii wide nocase
		$s2 = "gorentos2@firemail.cc" ascii wide nocase
		$s3 = "manager@mailtemp.ch" ascii wide nocase
		$s4 = "helprestoremanager@airmail.cc" ascii wide nocase
		$s5 = "supporthelp@airmail.cc" ascii wide nocase
		$s6 = "managerhelper@airmail.cc" ascii wide nocase
		$s7 = "helpteam@mail.ch" ascii wide nocase
		$s8 = "helpmanager@airmail.cc" ascii wide nocase
		$s9 = "support@sysmail.ch" ascii wide nocase

	condition:
		any of them
}
