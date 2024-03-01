rule SIGNATURE_BASE_APT30_Sample_31 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "9333870b-7eaa-54dd-a801-7292708fb592"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L819-L836"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "8b4271167655787be1988574446125eae5043aca"
		logic_hash = "003bfa9774d3e85829cc266d06417b86287986994995adfa7a2bd26c3648c07e"
		score = 75
		quality = 60
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "\\ZJRsv.tem" ascii
		$s1 = "forceguest" fullword ascii
		$s4 = "\\$NtUninstallKB570317$" ascii
		$s8 = "[Can'tGetIP]" fullword ascii
		$s14 = "QWERTY:,`/" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
