rule SIGNATURE_BASE_Hdroot_Sample_Jul17_1___FILE
{
	meta:
		description = "Detects HDRoot samples"
		author = "Florian Roth (Nextron Systems)"
		id = "06356f8a-bacd-51bc-a6f4-107983a9c16e"
		date = "2017-07-07"
		modified = "2023-12-05"
		reference = "Winnti HDRoot VT"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_winnti_hdroot.yar#L11-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "41127e6d70af4b095555285f3d5570fc4dbe2a7918664502057cdc4fed8fab33"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "6d2ad82f455becc8c830d000633a370857928c584246a7f41fe722cc46c0d113"

	strings:
		$s1 = "gleupdate.dll" fullword ascii
		$s2 = "\\DosDevices\\%ws\\system32\\%ws" wide
		$s3 = "l\\Driver\\nsiproxy" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <60KB and 3 of them )
}