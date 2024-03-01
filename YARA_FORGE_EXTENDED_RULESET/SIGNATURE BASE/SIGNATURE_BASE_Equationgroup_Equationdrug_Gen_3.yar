import "pe"

rule SIGNATURE_BASE_Equationgroup_Equationdrug_Gen_3 : FILE
{
	meta:
		description = "EquationGroup Malware - file mssld.dll"
		author = "Auto Generated"
		id = "f664ad78-1820-5434-94cc-94f98b32e654"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L1773-L1787"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "6b43280a94f1f5c62185f6b879126bcd258e9875beeb0f7ec1e3569494a60669"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "69dcc150468f7707cc8ef618a4cea4643a817171babfba9290395ada9611c63c"

	strings:
		$op1 = { f4 65 c6 45 f5 6c c6 45 f6 33 c6 45 f7 32 c6 45 }
		$op2 = { 36 c6 45 e6 34 c6 45 e7 50 c6 45 e8 72 c6 45 e9 }
		$op3 = { c6 45 e8 65 c6 45 e9 70 c6 45 ea 74 c6 45 eb 5f }

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and all of them )
}
