rule SIGNATURE_BASE_Duqu1_5_Modules
{
	meta:
		description = "Detection for Duqu 1.5 modules"
		author = "Silas Cutler (havex@chronicle.security)"
		id = "7239f5e1-c08f-566c-8998-f7dacc2c4a29"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://medium.com/chronicle-blog/who-is-gossipgirl-3b4170f846c0"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_duqu1_5_modules.yar#L2-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "bb3961e2b473c22c3d5939adeb86819eb846ccd07f5736abb5e897918580aace"
		logic_hash = "795107e227cfb73f6ea09fcdb078f8b57a30d47a2cb702b2d47cc936dea5ae9f"
		score = 75
		quality = 85
		tags = ""

	strings:
		$c1 = "%s(%d)disk(%d)fdisk(%d)"
		$c2 = "\\Device\\Floppy%d" wide
		$c3 = "BrokenAudio" wide
		$m1 = { 81 3F E9 18 4B 7E}
		$m2 = { 81 BC 18 F8 04 00 00 B3 20 EA B4 }

	condition:
		all of them
}
