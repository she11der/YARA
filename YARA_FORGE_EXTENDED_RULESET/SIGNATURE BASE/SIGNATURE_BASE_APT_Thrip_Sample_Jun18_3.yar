import "pe"

rule SIGNATURE_BASE_APT_Thrip_Sample_Jun18_3 : FILE
{
	meta:
		description = "Detects sample found in Thrip report by Symantec "
		author = "Florian Roth (Nextron Systems)"
		id = "67ea7ed1-954f-5b3e-b058-452be3b6fdfa"
		date = "2018-06-21"
		modified = "2023-12-05"
		reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_thrip.yar#L48-L62"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "f1617829ccf7da6ee2e9f692fbf1f61d3f1c6a17103db85190d6a8b4fca69328"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "0d2abdcaad99e102fdf6574b3dc90f17cb9d060c20e6ac4ff378875d3b91a840"

	strings:
		$s1 = "C:\\Windows\\SysNative\\cmd.exe" fullword ascii
		$s2 = "C:\\Windows\\SysNative\\sysprep\\cryptbase.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <60KB and all of them
}
