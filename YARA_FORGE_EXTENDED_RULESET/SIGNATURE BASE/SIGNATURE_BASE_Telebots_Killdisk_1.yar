rule SIGNATURE_BASE_Telebots_Killdisk_1 : FILE
{
	meta:
		description = "Detects TeleBots malware - KillDisk"
		author = "Florian Roth (Nextron Systems)"
		id = "111fc6bc-b790-51b9-81b7-a4716bb0aee9"
		date = "2016-12-14"
		modified = "2023-12-05"
		reference = "https://goo.gl/4if3HG"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_telebots.yar#L32-L51"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "e70d324c408bae1bb42b16f19cd0e6b87e8228c7480d571fef5266eee5695fd2"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "8246f709efa922a485e1ca32d8b0d10dc752618e8b3fce4d3dd58d10e4a6a16d"

	strings:
		$s1 = "Plug-And-Play Support Service" fullword wide
		$s2 = " /c \"echo Y|" fullword wide
		$s3 = "-set=06.12.2016#09:30 -est=1410" fullword ascii
		$s4 = "%d.%d.%d#%d:%d" fullword ascii
		$s5 = " /T /C /G " fullword wide
		$s6 = "[-] > %ls" fullword wide
		$s7 = "[+] > %ls" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <500KB and 4 of them ) or (6 of them )
}
