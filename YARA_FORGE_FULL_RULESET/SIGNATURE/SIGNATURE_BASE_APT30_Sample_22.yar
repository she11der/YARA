rule SIGNATURE_BASE_APT30_Sample_22 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "6c1b3dd2-4383-51a2-9185-2365a4d1e784"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt30_backspace.yar#L577-L595"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "0d17a58c24753e5f8fd5276f62c8c7394d8e1481"
		logic_hash = "88a45d248eba7b9776e2e7d345d2948e00a94a7e359acb89d1943be55ab342ad"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "(\\TEMP" fullword ascii
		$s2 = "Windows\\Cur" fullword ascii
		$s3 = "LSSAS.exeJ" fullword ascii
		$s4 = "QC:\\WINDOWS" fullword ascii
		$s5 = "System Volume" fullword ascii
		$s8 = "PROGRAM FILE" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
