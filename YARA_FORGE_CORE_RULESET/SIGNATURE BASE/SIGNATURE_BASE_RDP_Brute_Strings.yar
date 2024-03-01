rule SIGNATURE_BASE_RDP_Brute_Strings
{
	meta:
		description = "Detects RDP brute forcer from NCSC report"
		author = "NCSC"
		id = "d6f0cdbc-a910-5826-b25a-61c2924f8e2a"
		date = "2018-04-06"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_ncsc_report_04_2018.yar#L151-L174"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "8234bf8a1b53efd2a452780a69666d1aedcec9eb1bb714769283ccc2c2bdcc65"
		logic_hash = "80c51d82a57271409d298b5175505c4234a6c3ec8a8763c93b669d1f0a8d59ba"
		score = 75
		quality = 85
		tags = ""

	strings:
		$ = "RDP Brute" ascii wide
		$ = "RdpChecker" ascii
		$ = "RdpBrute" ascii
		$ = "Brute_Count_Password" ascii
		$ = "BruteIPList" ascii
		$ = "Chilkat_Socket_Key" ascii
		$ = "Brute_Sync_Stat" ascii
		$ = "(Error! Hyperlink reference not valid.)" wide
		$ = "BadRDP" wide
		$ = "GoodRDP" wide
		$ = "@echo off{0}:loop{0}del {1}{0}if exist {1} goto loop{0}del {2}{0}del \"{2}\"" wide
		$ = "Coded by z668" wide

	condition:
		4 of them
}
