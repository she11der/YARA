rule SIGNATURE_BASE_APT30_Sample_16 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt30_backspace.yar#L389-L407"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "066d06ac08b48d3382d46bbeda6ad411b6d6130e"
		logic_hash = "59ea90ac0590bd87a48fabf1a3fa7ece31560b980b738a34227937bbf82a1c55"
		score = 75
		quality = 60
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "\\Temp1020.txt" ascii
		$s1 = "cmcbqyjs" fullword ascii
		$s2 = "SPVSWh\\" fullword ascii
		$s4 = "PSShxw@" fullword ascii
		$s5 = "VWhHw@" fullword ascii
		$s7 = "SVWhHw@" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
