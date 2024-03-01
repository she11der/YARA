import "pe"

rule SIGNATURE_BASE_Oilrig_Campaign_Reconnaissance : FILE
{
	meta:
		description = "Detects Windows discovery commands - known from OilRig Campaign"
		author = "Florian Roth (Nextron Systems)"
		id = "a4fe24b8-290a-5a4a-9f81-bbbd9aae6c6e"
		date = "2016-10-12"
		modified = "2023-12-05"
		reference = "https://goo.gl/QMRZ8K"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_oilrig.yar#L151-L166"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "04c9f482c0c4abc1bf316459dc3085154defadb0fd5fe74ff274d8b3ee807b7f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "5893eae26df8e15c1e0fa763bf88a1ae79484cdb488ba2fc382700ff2cfab80c"

	strings:
		$s1 = "whoami & hostname & ipconfig /all" ascii
		$s2 = "net user /domain 2>&1 & net group /domain 2>&1" ascii
		$s3 = "net group \"domain admins\" /domain 2>&1 & " ascii

	condition:
		( filesize <1KB and 1 of them )
}
