import "pe"

rule SIGNATURE_BASE_Disclosed_0Day_Pocs_Lpe_2 : FILE
{
	meta:
		description = "Detects POC code from disclosed 0day hacktool set"
		author = "Florian Roth (Nextron Systems)"
		id = "9326bbae-81ee-588e-8581-628b47d348f8"
		date = "2017-07-07"
		modified = "2023-12-05"
		reference = "Disclosed 0day Repos"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L3787-L3802"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "e9ca23e4375674ea189d5e9de015f6a1ae16c30d35378580bdc8f42007b716df"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "b4f3787a19b71c47bc4357a5a77ffb456e2f71fd858079d93e694a6a79f66533"

	strings:
		$s1 = "\\cmd.exe\" /k wusa c:\\users\\" ascii
		$s2 = "D:\\gitpoc\\UAC\\src\\x64\\Release\\lpe.pdb" fullword ascii
		$s3 = "Folder Created: " fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <700KB and 2 of them )
}
