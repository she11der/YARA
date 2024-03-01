rule SIGNATURE_BASE_SUSP_PDB_Strings_Keylogger_Backdoor : HIGHVOL FILE
{
	meta:
		description = "Detects PDB strings used in backdoors or keyloggers"
		author = "Florian Roth (Nextron Systems)"
		id = "190daadb-0de6-5665-a241-95c374dbda47"
		date = "2018-03-23"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_suspicious_strings.yar#L109-L130"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "9a842ff8cd8be98a2e37a81706a9c594e8bf1bcc6bd3cedfe4747cd52f6044f5"
		score = 65
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$ = "\\Release\\PrivilegeEscalation"
		$ = "\\Release\\KeyLogger"
		$ = "\\Debug\\PrivilegeEscalation"
		$ = "\\Debug\\KeyLogger"
		$ = "Backdoor\\KeyLogger_"
		$ = "\\ShellCode\\Debug\\"
		$ = "\\ShellCode\\Release\\"
		$ = "\\New Backdoor"

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and 1 of them
}
