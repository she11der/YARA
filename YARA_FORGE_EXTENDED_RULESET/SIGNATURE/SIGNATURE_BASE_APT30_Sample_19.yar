rule SIGNATURE_BASE_APT30_Sample_19 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"
		date = "2015-04-03"
		modified = "2023-01-06"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L491-L517"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "cfa438449715b61bffa20130df8af778ef011e15"
		logic_hash = "9127ae31c5b818a2759f9d33c74c8631079539e7fa8e49e5514b016df2624065"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s0 = "C:\\Program Files\\Common Files\\System\\wab32" fullword ascii
		$s1 = "%s,Volume:%s,Type:%s,TotalSize:%uMB,FreeSize:%uMB" fullword ascii
		$s2 = "\\TEMP\\" ascii
		$s3 = "\\Temporary Internet Files\\" ascii
		$s5 = "%s TotalSize:%u Bytes" fullword ascii
		$s6 = "This Disk Maybe a Encrypted Flash Disk!" fullword ascii
		$s7 = "User:%-32s" fullword ascii
		$s8 = "\\Desktop\\" ascii
		$s9 = "%s.%u_%u" fullword ascii
		$s10 = "Nick:%-32s" fullword ascii
		$s11 = "E-mail:%-32s" fullword ascii
		$s13 = "%04u-%02u-%02u %02u:%02u:%02u" fullword ascii
		$s14 = "Type:%-8s" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and 8 of them
}
