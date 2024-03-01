rule SIGNATURE_BASE_CN_Honker_Webrobot : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file WebRobot.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "8b6350b6-17ea-5f44-a42a-875d55bb2de8"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L1007-L1023"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "af054994c911b4301490344fca4bb19a9f394a8f"
		logic_hash = "7d7fc9fb9156aa20993dcb809f4e1d3d357f6826dcac7e628dbe6e0f81e5a61a"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "%d-%02d-%02d %02d^%02d^%02d ScanReprot.htm" fullword ascii
		$s2 = "\\log\\ProgramDataFile.dat" ascii
		$s3 = "\\data\\FilterKeyword.txt" ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and all of them
}
