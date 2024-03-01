rule SIGNATURE_BASE_APT30_Generic_F : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "cff8b921-9afc-5a52-84cb-825de33fc86e"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt30_backspace.yar#L597-L615"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "4997b52e0cc12a1a0c84cec3565dd9e6b486ccef4eb8791c566c7a534d36e3ff"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "09010917cd00dc8ddd21aeb066877aa2"
		hash2 = "4c10a1efed25b828e4785d9526507fbc"
		hash3 = "b7b282c9e3eca888cbdb5a856e07e8bd"
		hash4 = "df1799845b51300b03072c6569ab96d5"

	strings:
		$s0 = "\\~zlzl.exe" ascii
		$s2 = "\\Internet Exp1orer" ascii
		$s3 = "NodAndKabIsExcellent" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
