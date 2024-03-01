rule SIGNATURE_BASE_CN_Honker_Syconfig : FILE
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file syconfig.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "3850007d-20d5-5b10-a549-dc4655877c6e"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_scripts.yar#L223-L237"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "ff75353df77d610d3bccfbffb2c9dfa258b2fac9"
		logic_hash = "6b7f918b83bac84df5ac6b247d4162dd385aba0a32570366c62fc4830199e86e"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s9 = "Hashq.CrackHost+FormUnit" fullword ascii

	condition:
		uint16(0)==0x0100 and filesize <18KB and all of them
}
