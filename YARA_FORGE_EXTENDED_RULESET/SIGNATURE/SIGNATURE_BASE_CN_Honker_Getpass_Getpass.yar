rule SIGNATURE_BASE_CN_Honker_Getpass_Getpass : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file GetPass.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "999d0ac0-a112-53db-9dbe-10fa4419cfae"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L2188-L2204"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "d18d952b24110b83abd17e042f9deee679de6a1a"
		logic_hash = "90d802da512f5d460eda6d644660711601d361e2402522d085d3225931a3fca3"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "\\only\\Desktop\\" ascii
		$s2 = "To Run As Administuor" ascii
		$s3 = "Key to EXIT ... & pause > nul" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}
