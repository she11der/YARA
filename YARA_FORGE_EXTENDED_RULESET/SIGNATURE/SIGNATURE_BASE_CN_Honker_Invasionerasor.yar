rule SIGNATURE_BASE_CN_Honker_Invasionerasor : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file InvasionErasor.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "03ccb643-9f92-5278-a358-65f56cf19ccc"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L2128-L2146"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "b37ecd9ee6b137a29c9b9d2801473a521b168794"
		logic_hash = "d2f742693682e9409284706a3eb63536a576cb162629bf76bfabf2e0210984a3"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "c:\\windows\\system32\\config\\*.*" fullword wide
		$s2 = "c:\\winnt\\*.txt" fullword wide
		$s3 = "Command1" fullword ascii
		$s4 = "Win2003" fullword ascii
		$s5 = "Win 2000" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <60KB and all of them
}
