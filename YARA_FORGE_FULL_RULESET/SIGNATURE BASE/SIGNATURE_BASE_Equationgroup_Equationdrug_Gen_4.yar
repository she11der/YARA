import "pe"

rule SIGNATURE_BASE_Equationgroup_Equationdrug_Gen_4 : FILE
{
	meta:
		description = "EquationGroup Malware - file PC_Level4_flav_dll"
		author = "Auto Generated"
		id = "e3fc376b-f7cc-5dfa-bcf4-4991962a4cf9"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L1610-L1624"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "3046cbfa4b4f5eb5d0efc1b2b658567391b0c219650437088a0d6c179e9235fb"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "227faeb770ba538fb85692b3dfcd00f76a0a5205d1594bd0969a1e535ee90ee1"

	strings:
		$op1 = { 11 8b da 23 df 8d 1c 9e c1 fb 02 33 da 23 df 33 }
		$op2 = { c3 0c 57 8b 3b eb 27 8b f7 83 7e 08 00 8b 3f 74 }
		$op3 = { 00 0f b7 5e 14 8d 5c 33 18 8b c3 2b 45 08 50 ff }

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}
