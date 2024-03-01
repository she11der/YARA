rule SIGNATURE_BASE_Blackenergy_Killdisk_1 : FILE
{
	meta:
		description = "Detects KillDisk malware from BlackEnergy"
		author = "Florian Roth (Nextron Systems)"
		id = "304e7aa3-48d3-5015-aaf1-6b1df2441b75"
		date = "2016-01-03"
		modified = "2023-12-05"
		reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_blackenergy.yar#L88-L115"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "fa64434422a16166938b9eede9c50b79bae90632f1500e6529dcf26dbebe50f1"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "11b7b8a7965b52ebb213b023b6772dd2c76c66893fc96a18a9a33c8cf125af80"
		hash2 = "5d2b1abc7c35de73375dd54a4ec5f0b060ca80a1831dac46ad411b4fe4eac4c6"
		hash3 = "c7536ab90621311b526aefd56003ef8e1166168f038307ae960346ce8f75203d"
		hash4 = "f52869474834be5a6b5df7f8f0c46cbc7e9b22fa5cb30bee0f363ec6eb056b95"

	strings:
		$s0 = "system32\\cmd.exe" fullword ascii
		$s1 = "system32\\icacls.exe" fullword wide
		$s2 = "/c del /F /S /Q %c:\\*.*" fullword ascii
		$s3 = "shutdown /r /t %d" fullword ascii
		$s4 = "/C /Q /grant " fullword wide
		$s5 = "%08X.tmp" fullword ascii
		$s6 = "/c format %c: /Y /X /FS:NTFS" fullword ascii
		$s7 = "/c format %c: /Y /Q" fullword ascii
		$s8 = "taskhost.exe" fullword wide
		$s9 = "shutdown.exe" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <500KB and 8 of them
}
