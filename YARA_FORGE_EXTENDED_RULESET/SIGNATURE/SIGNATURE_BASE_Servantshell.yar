rule SIGNATURE_BASE_Servantshell : FILE
{
	meta:
		description = "Detects Servantshell malware"
		author = "Arbor Networks ASERT Nov 2015"
		id = "f41e9191-0be1-59f7-9be4-e39c8a37b2c5"
		date = "2017-02-02"
		modified = "2023-12-05"
		reference = "https://tinyurl.com/jmp7nrs"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_servantshell.yar#L1-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "739057dc95831c9ed35981b40c606ecd0b3fd2118b42ed7c09e200dc0bc395db"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$string1 = "SelfDestruction.cpp"
		$string2 = "SvtShell.cpp"
		$string3 = "InitServant"
		$string4 = "DeinitServant"
		$string5 = "CheckDT"

	condition:
		uint16(0)==0x5a4d and all of them
}
