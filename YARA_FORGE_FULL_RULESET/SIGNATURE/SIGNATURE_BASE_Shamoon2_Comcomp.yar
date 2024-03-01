rule SIGNATURE_BASE_Shamoon2_Comcomp : FILE
{
	meta:
		description = "Detects Shamoon 2.0 Communication Components"
		author = "Florian Roth (Nextron Systems) (with Binar.ly)"
		id = "72068264-4f71-59fb-b3d8-938285ec8c7f"
		date = "2016-12-01"
		modified = "2023-12-05"
		reference = "https://goo.gl/jKIfGB"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_shamoon2.yar#L30-L48"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "edebdbcf17bd9fadc67c7d76839cf569f0ea20127d4e0d216411c35e9ba54208"
		score = 70
		quality = 85
		tags = "FILE"
		hash1 = "61c1c8fc8b268127751ac565ed4abd6bdab8d2d0f2ff6074291b2d54b0228842"

	strings:
		$s1 = "mkdir %s%s > nul 2>&1" fullword ascii
		$s2 = "p[%s%s%d.%s" fullword ascii
		$op1 = { 04 32 cb 88 04 37 88 4c 37 01 88 54 37 02 83 c6 }
		$op2 = { c8 02 d2 c0 e9 06 02 d2 24 3f 02 d1 88 45 fb 8d }
		$op3 = { 0c 3b 40 8d 4e 01 47 3b c1 7c d8 83 fe 03 7d 1c }

	condition:
		uint16(0)==0x5a4d and filesize <500KB and ( all of ($s*) or all of ($op*))
}
