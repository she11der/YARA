import "pe"

rule SIGNATURE_BASE_Xyzcmd_Zip_Folder_Readme
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file Readme.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "cee0f8c3-f947-50a5-ae8c-4ce83ef5e433"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L2109-L2123"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "967cb87090acd000d22e337b8ce4d9bdb7c17f70"
		logic_hash = "38d69eee78ff8fa2ad064871481bd1b8a926146922952c7e199d27c809d0c980"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s3 = "3.xyzcmd \\\\RemoteIP /user:Administrator /pwd:1234 /nowait trojan.exe" fullword ascii
		$s20 = "XYZCmd V1.0" fullword ascii

	condition:
		all of them
}
