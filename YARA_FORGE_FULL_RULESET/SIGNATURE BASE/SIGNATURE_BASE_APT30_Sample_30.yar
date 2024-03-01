rule SIGNATURE_BASE_APT30_Sample_30 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "787b288a-6fb4-5483-af76-933651ec6d58"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt30_backspace.yar#L800-L817"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "3b684fa40b4f096e99fbf535962c7da5cf0b4528"
		logic_hash = "5ecfc8d53b768f624c8765f70708bfaae5396d7aa6b0335f7c656f4350649c5d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "5.1.2600.2180 (xpsp_sp2_rtm.040803-2158)" fullword wide
		$s3 = "RnhwtxtkyLRRMf{jJ}ny" fullword ascii
		$s4 = "RnhwtxtkyLRRJ}ny" fullword ascii
		$s5 = "ZRLDownloadToFileA" fullword ascii
		$s9 = "5.1.2600.2180" fullword wide

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
