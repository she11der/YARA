rule SIGNATURE_BASE_CN_Honker_Happy_Happy : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Happy.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "6e6c806d-e784-507f-b327-3b9f2510422b"
		date = "2015-06-23"
		modified = "2023-01-27"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L665-L683"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "92067d8dad33177b5d6c853d4d0e897f2ee846b0"
		logic_hash = "667cd6629ca49f2200fdc0a5eb28c77c412ca25313fd9a8afb77dedfa66d2fa1"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<form.*?method=\"post\"[\\s\\S]*?</form>" fullword wide
		$s2 = "domainscan.exe" fullword wide
		$s3 = "http://www.happysec.com/" wide
		$s4 = "cmdshell" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <655KB and 2 of them
}
