rule SIGNATURE_BASE_APT30_Sample_6 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "2f19809c-09fc-51bf-9a20-6b95099a92dd"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt30_backspace.yar#L129-L143"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "00e69b059ad6b51b76bc476a115325449d10b4c0"
		logic_hash = "139719139056f575967629f0153e0a05239bc26f61f6d4324cfb6a816518c3df"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "GreateProcessA" fullword ascii
		$s1 = "Ternel32.dll" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
