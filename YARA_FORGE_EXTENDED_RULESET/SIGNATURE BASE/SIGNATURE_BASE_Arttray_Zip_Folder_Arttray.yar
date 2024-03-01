import "pe"

rule SIGNATURE_BASE_Arttray_Zip_Folder_Arttray
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file ArtTray.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "d29909a4-8663-54c7-8f0e-68b15def869f"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L2572-L2588"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "ee1edc8c4458c71573b5f555d32043cbc600a120"
		logic_hash = "225be71bfd047331399162941edf06c72d2fd1afa04c78cbc51099665f50883b"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "http://www.brigsoft.com" fullword wide
		$s2 = "ArtTrayHookDll.dll" fullword ascii
		$s3 = "ArtTray Version 1.0 " fullword wide
		$s16 = "TRM_HOOKCALLBACK" fullword ascii

	condition:
		all of them
}
