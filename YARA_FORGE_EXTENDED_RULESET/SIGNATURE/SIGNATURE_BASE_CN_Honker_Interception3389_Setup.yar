rule SIGNATURE_BASE_CN_Honker_Interception3389_Setup : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file setup.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "7250ff73-6b08-56a4-b2bc-081060d1fa2d"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L1353-L1371"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "f5b2f86f8e7cdc00aa1cb1b04bc3d278eb17bf5c"
		logic_hash = "d3f543683810a985a190cc3ea8edb7bfcd316d56a13d45c6532c488a4536ad0a"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\%s" fullword ascii
		$s1 = "%s\\temp\\temp%d.bat" fullword ascii
		$s5 = "EventStartShell" fullword ascii
		$s6 = "del /f /q \"%s\"" fullword ascii
		$s7 = "\\wminotify.dll" ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and all of them
}
