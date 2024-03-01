rule SIGNATURE_BASE_Xdedic_Sysscan_Unpacked : CRIMEWARE FILE
{
	meta:
		description = "Detects SysScan APT tool"
		author = " Kaspersky Lab"
		id = "4f5d37b3-e3aa-51ec-b36e-b494c8abe227"
		date = "2016-03-14"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/research/75027/xdedic-the-shady-world-of-hacked-servers-for-sale/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_sysscan.yar#L1-L27"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "df0834e89c512721547001c910c1461f028a46e954dd51017d4e8bde7893d04a"
		score = 75
		quality = 85
		tags = "CRIMEWARE, FILE"
		maltype = "crimeware"
		type = "crimeware"
		filetype = "Win32 EXE"
		version = "1.0"
		hash1 = "fac495be1c71012682ebb27092060b43"
		hash2 = "e8cc69231e209db7968397e8a244d104"
		hash3 = "a53847a51561a7e76fd034043b9aa36d"
		hash4 = "e8691fa5872c528cd8e72b82e7880e98"
		hash5 = "F661b50d45400e7052a2427919e2f777"

	strings:
		$a1 = "/c ping -n 2 127.0.0.1 & del \"SysScan.exe\"" ascii wide
		$a2 = "SysScan DEBUG Mode!!!" ascii wide
		$a3 = "This rechecking? (set 0/1 or press enter key)" ascii wide
		$a4 = "http://37.49.224.144:8189/manual_result" ascii wide
		$b1 = "Checker end work!" ascii wide
		$b2 = "Trying send result..." ascii wide

	condition:
		uint16(0)==0x5A4D and filesize <5000000 and ( any of ($a*) or all of ($b*))
}
