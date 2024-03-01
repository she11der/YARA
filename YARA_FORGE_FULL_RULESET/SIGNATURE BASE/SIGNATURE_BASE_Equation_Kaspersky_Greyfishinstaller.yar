rule SIGNATURE_BASE_Equation_Kaspersky_Greyfishinstaller
{
	meta:
		description = "Equation Group Malware - Grey Fish"
		author = "Florian Roth (Nextron Systems)"
		id = "ea16b51c-755e-5f08-a209-d21a1ed30fcf"
		date = "2015-02-16"
		modified = "2023-12-05"
		reference = "http://goo.gl/ivt8EW"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/spy_equation_fiveeyes.yar#L174-L189"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "58d15d1581f32f36542f3e9fb4b1fc84d2a6ba35"
		logic_hash = "dae6963f3210503c6c86c818a9cd6f309ba7876f14ca42966097023d474a2366"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "DOGROUND.exe" fullword wide
		$s1 = "Windows Configuration Services" fullword wide
		$s2 = "GetMappedFilenameW" fullword ascii

	condition:
		all of them
}
