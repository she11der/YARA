rule SIGNATURE_BASE_Goldeneyeransomware_Dropper_Malformedzoomit : FILE
{
	meta:
		description = "Auto-generated rule"
		author = "Florian Roth (Nextron Systems)"
		id = "6ebf2d13-7d58-5a1b-a836-66d533f408e8"
		date = "2016-12-06"
		modified = "2023-12-05"
		reference = "https://goo.gl/jp2SkT"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/crime_goldeneye.yar#L26-L40"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "c18405a272c9210973e3184b8267306919cba8795b12d5982a9e3e8f748f9782"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "b5ef16922e2c76b09edd71471dd837e89811c5e658406a8495c1364d0d9dc690"

	strings:
		$s1 = "ZoomIt - Sysinternals: www.sysinternals.com" fullword ascii
		$n1 = "Mark Russinovich" wide

	condition:
		( uint16(0)==0x5a4d and filesize <800KB and $s1 and not $n1)
}
