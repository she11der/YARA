rule SIGNATURE_BASE_Simattacker___Vrsion_1_0_0___Priv8_4_My_Friend_Php
{
	meta:
		description = "Semi-Auto-generated  - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "8a34f4fd-337d-5eb4-b7b7-4adb1c2b7937"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L3792-L3804"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "089ff24d978aeff2b4b2869f0c7d38a3"
		logic_hash = "46bc4063d06b4af3e4e61e1e998d489e974e76f17363c9777b8afc39ff21f698"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "SimAttacker - Vrsion : 1.0.0 - priv8 4 My friend"
		$s3 = " fputs ($fp ,\"\\n*********************************************\\nWelcome T0 Sim"
		$s4 = "echo \"<a target='_blank' href='?id=fm&fedit=$dir$file'><span style='text-decora"

	condition:
		1 of them
}
