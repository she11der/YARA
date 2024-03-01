rule SIGNATURE_BASE_Equation_Kaspersky_Suspiciousstring : FILE
{
	meta:
		description = "Equation Group Malware - suspicious string found in sample"
		author = "Florian Roth (Nextron Systems)"
		id = "a5f203a7-0c50-5658-89f4-44533ed4eef0"
		date = "2015-02-17"
		modified = "2023-12-05"
		reference = "http://goo.gl/ivt8EW"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/spy_equation_fiveeyes.yar#L346-L364"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "dd7f72c2263a3af9b8c9072b415a3b066e821e000b52ddd684ecb6b80a99067a"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "i386\\DesertWinterDriver.pdb" fullword
		$s2 = "Performing UR-specific post-install..."
		$s3 = "Timeout waiting for the \"canInstallNow\" event from the implant-specific EXE!"
		$s4 = "STRAITSHOOTER30.exe"
		$s5 = "standalonegrok_2.1.1.1"
		$s6 = "c:\\users\\rmgree5\\"

	condition:
		uint16(0)==0x5a4d and filesize <500000 and all of ($s*)
}
