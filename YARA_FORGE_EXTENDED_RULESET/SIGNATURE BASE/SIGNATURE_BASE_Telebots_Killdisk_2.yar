rule SIGNATURE_BASE_Telebots_Killdisk_2 : FILE
{
	meta:
		description = "Detects TeleBots malware - KillDisk"
		author = "Florian Roth (Nextron Systems)"
		id = "7797187f-c94b-5323-ae43-2dc001f0b481"
		date = "2016-12-14"
		modified = "2023-12-05"
		reference = "https://goo.gl/4if3HG"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_telebots.yar#L53-L68"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "e4ae09a226c4eecae18e685423ef30b3776be518609f89a078c647fe8ee00f19"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "26173c9ec8fd1c4f9f18f89683b23267f6f9d116196ed15655e9cb453af2890e"

	strings:
		$s1 = "Plug-And-Play Support Service" fullword wide
		$s2 = " /c \"echo Y|" fullword wide
		$s3 = "%d.%d.%d#%d:%d" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <500KB and all of them )
}
