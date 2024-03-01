rule SIGNATURE_BASE_MAL_Enfal_Nov22 : FILE
{
	meta:
		description = "Detects a certain type of Enfal Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "9dcba14e-2175-5da0-8629-5b952c213f6c"
		date = "2015-02-10"
		modified = "2023-01-06"
		old_rule_name = "Enfal_Malware"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.enfal"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/crime_enfal.yar#L1-L25"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "bf349ba2b7bd635808b4ee23c6286e7dd403fbc185c6b59f0bb1fbf47ba7d9bb"
		score = 75
		quality = 85
		tags = "FILE"
		hash2 = "42fa6241ab94c73c7ab386d600fae70da505d752daab2e61819a0142b531078a"
		hash2 = "bf433f4264fa3f15f320b35e773e18ebfe94465d864d3f4b2a963c3e5efd39c2"

	strings:
		$xop1 = { 00 00 83 c9 ff 33 c0 f2 ae f7 d1 49 b8 ff 8f 01 00 2b c1 }
		$s1 = "POWERPNT.exe" fullword ascii
		$s2 = "%APPDATA%\\Microsoft\\Windows\\" ascii
		$s3 = "%HOMEPATH%" fullword ascii
		$s4 = "Server2008" fullword ascii
		$s5 = "%ComSpec%" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and (1 of ($x*) or 3 of ($s*))
}
