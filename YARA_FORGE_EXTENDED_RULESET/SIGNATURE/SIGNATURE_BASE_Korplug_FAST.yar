rule SIGNATURE_BASE_Korplug_FAST : FILE
{
	meta:
		description = "Rule to detect Korplug/PlugX FAST variant"
		author = "Florian Roth (Nextron Systems)"
		id = "85c6c460-2902-5bfa-be58-a2b62e3b882e"
		date = "2015-08-20"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_korplug_fast.yar#L1-L27"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "c437465db42268332543fbf6fd6a560ca010f19e0fd56562fb83fb704824b371"
		logic_hash = "31aeb634eecc0f93353432b0dde113bfb54810ea74b02f959447a1d42e7e9e1b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "%s\\rundll32.exe \"%s\", ShadowPlay" fullword ascii
		$a1 = "ShadowPlay" fullword ascii
		$s1 = "%s\\rundll32.exe \"%s\"," fullword ascii
		$s2 = "nvdisps.dll" fullword ascii
		$s3 = "%snvdisps.dll" fullword ascii
		$s4 = "\\winhlp32.exe" ascii
		$s5 = "nvdisps_user.dat" fullword ascii
		$s6 = "%snvdisps_user.dat" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <500KB and ($x1 or ($a1 and 1 of ($s*)) or 4 of ($s*))
}
