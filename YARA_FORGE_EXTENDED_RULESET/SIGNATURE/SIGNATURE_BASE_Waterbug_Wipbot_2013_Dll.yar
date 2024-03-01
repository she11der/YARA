rule SIGNATURE_BASE_Waterbug_Wipbot_2013_Dll
{
	meta:
		description = "Symantec Waterbug Attack - Trojan.Wipbot 2014 Down.dll component"
		author = "Symantec Security Response"
		id = "2aae09a3-6e59-5951-941e-c1f82aada979"
		date = "2015-01-22"
		modified = "2023-12-05"
		reference = "http://t.co/rF35OaAXrl"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_waterbug.yar#L17-L32"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "f29ff81d62bd6bea776aeddc0725b034624f836c234441f63a8b697e959d3f8d"
		score = 75
		quality = 85
		tags = ""

	strings:
		$string1 = "/%s?rank=%s"
		$string2 = "ModuleStart\x00ModuleStop\x00start"
		$string3 = "1156fd22-3443-4344-c4ffff"
		$string4 = "read\x20file\x2E\x2E\x2E\x20error\x00\x00"

	condition:
		2 of them
}
