rule SIGNATURE_BASE_APT30_Sample_9 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "bf24bb57-aff9-579c-b8a2-265a6d2a06d0"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L242-L263"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "442bf8690401a2087a340ce4a48151c39101652f"
		logic_hash = "0c5465bdafcbca02f855a0cba1fbb4c19d8d21b714dbe777b942dcd1a7acb257"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "\\Windo" ascii
		$s2 = "oHHOSTR" ascii
		$s3 = "Softwa]\\Mic" ascii
		$s4 = "Startup'T" ascii
		$s6 = "Ora\\%^" ascii
		$s7 = "\\Ohttp=r" ascii
		$s17 = "help32Snapshot0L" ascii
		$s18 = "TimUmoveH" ascii
		$s20 = "WideChc[lobalAl" ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
