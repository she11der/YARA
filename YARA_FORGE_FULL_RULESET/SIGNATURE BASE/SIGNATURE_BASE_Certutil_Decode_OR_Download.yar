rule SIGNATURE_BASE_Certutil_Decode_OR_Download : FILE
{
	meta:
		description = "Certutil Decode"
		author = "Florian Roth (Nextron Systems)"
		id = "63bdefd2-225a-56d5-b615-5e236c97f050"
		date = "2017-08-29"
		modified = "2023-10-19"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_mal_scripts.yar#L70-L93"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "5640dcfedc028cc40b0376d328758b504eb1ff860da94648b435eadb760d9724"
		score = 40
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$a1 = "certutil -decode " ascii wide
		$a2 = "certutil  -decode " ascii wide
		$a3 = "certutil.exe -decode " ascii wide
		$a4 = "certutil.exe  -decode " ascii wide
		$a5 = "certutil -urlcache -split -f http" ascii wide
		$a6 = "certutil.exe -urlcache -split -f http" ascii wide
		$fp_msi = { 52 00 6F 00 6F 00 74 00 20 00 45 00 6E 00 74 00 72 00 79 }

	condition:
		filesize <700KB and 1 of ($a*) and not 1 of ($fp*)
}
