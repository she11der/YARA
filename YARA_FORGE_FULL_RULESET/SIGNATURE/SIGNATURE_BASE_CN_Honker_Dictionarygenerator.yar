rule SIGNATURE_BASE_CN_Honker_Dictionarygenerator : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file DictionaryGenerator.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "29ce6f8c-3092-5917-ab31-aaed7834c500"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1158-L1173"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b3071c64953e97eeb2ca6796fab302d8a77d27bc"
		logic_hash = "228bdbca3eb206e22a130e91caa2486174efba9356dbee67e80333c0cf0bb643"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "`PasswordBuilder" fullword ascii
		$s2 = "cracker" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3650KB and all of them
}
