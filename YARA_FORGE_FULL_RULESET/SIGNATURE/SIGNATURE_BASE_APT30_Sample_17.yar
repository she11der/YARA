rule SIGNATURE_BASE_APT30_Sample_17 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt30_backspace.yar#L431-L445"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "c3aa52ff1d19e8fc6704777caf7c5bd120056845"
		logic_hash = "43913151325fbce993dbfec0acf64ca835b12270c47156ae81b0ce4f32c7bde1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Nkfvtyvn}]ty}ztU" fullword ascii
		$s4 = "IEXPL0RE" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
