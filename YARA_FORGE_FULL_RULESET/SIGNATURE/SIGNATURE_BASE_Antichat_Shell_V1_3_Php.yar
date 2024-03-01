rule SIGNATURE_BASE_Antichat_Shell_V1_3_Php
{
	meta:
		description = "Semi-Auto-generated  - file Antichat Shell v1.3.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "856cf977-24da-58e0-b6d2-820c92075ecc"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L4446-L4458"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "40d0abceba125868be7f3f990f031521"
		logic_hash = "566c324f3bf44ce9f32ddad82a8d3daa87a8a75b5ca0c8286bc912a8ae4ac8e9"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "Antichat"
		$s1 = "Can't open file, permission denide"
		$s2 = "$ra44"

	condition:
		2 of them
}
