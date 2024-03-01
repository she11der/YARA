rule SIGNATURE_BASE_Empire_Install_SSP : FILE
{
	meta:
		description = "Detects Empire component - file Install-SSP.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "06bbdcc5-c48b-5753-88a2-5c962d1b986f"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_empire.yar#L76-L89"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "bf0966d0141d4606983f267face635ef5fddbc73282f02f0a0ae6fcf89f2e6dc"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "7fd921a23950334257dda57b99e03c1e1594d736aab2dbfe9583f99cd9b1d165"

	strings:
		$s1 = "Install-SSP -Path .\\mimilib.dll" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <20KB and 1 of them ) or all of them
}
