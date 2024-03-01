rule SIGNATURE_BASE_CN_Honker_Alien_Command : FILE
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file command.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "55dd10c9-f7dc-5ee2-a47d-dab8cc7b60e6"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_scripts.yar#L291-L306"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "5896b74158ef153d426fba76c2324cd9c261c709"
		logic_hash = "a55be30fdb6598669d144308af5a9b6a21ab6140c75fdfc18cecf5d9add4a530"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "for /d %i in (E:\\freehost\\*) do @echo %i" fullword ascii
		$s1 = "/c \"C:\\windows\\temp\\cscript\" C:\\windows\\temp\\iis.vbs" fullword ascii

	condition:
		filesize <8KB and all of them
}
