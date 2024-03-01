rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_PC_Level_Generic : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "7ff3d0b0-7a70-561e-9c45-d1f9dbccefe9"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L3045-L3075"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "ddb3441b62b477ab7e3406a22e2a246b60c1d1d25e4acf52ee452a2dfac2daf7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "7a6488dd13936e505ec738dcc84b9fec57a5e46aab8aff59b8cfad8f599ea86a"
		hash2 = "0e3cfd48732d0b301925ea3ec6186b62724ec755ed40ed79e7cd6d3df511b8a0"
		hash3 = "d1d6e3903b6b92cc52031c963e2031b5956cadc29cc8b3f2c8f38be20f98a4a7"
		hash4 = "25a2549031cb97b8a3b569b1263c903c6c0247f7fff866e7ec63f0add1b4921c"
		hash5 = "591abd3d7ee214df25ac25682b673f02219da108d1384261052b5167a36a7645"
		hash6 = "6b71db2d2721ac210977a4c6c8cf7f75a8f5b80b9dbcece1bede1aec179ed213"
		hash7 = "7be4c05cecb920f1010fc13086635591ad0d5b3a3a1f2f4b4a9be466a1bd2b76"
		hash8 = "f9cbccdbdf9ffd2ebf1ee84d0ddddd24a61dbe0858ab7f0131bef6c7b9a19131"
		hash9 = "3cf7a01bdf8e73769c80b75ca269b506c33464d81f574ded8bb20caec2d4cd13"
		hash10 = "a87a871fe32c49862ed68fda99d92efd762a33ababcd9b6b2b909f2e01f59c16"

	strings:
		$s1 = "wshtcpip.WSHGetSocketInformation" fullword ascii
		$s2 = "\\\\.\\%hs" fullword ascii
		$s3 = ".?AVResultIp@Mini_Mcl_Cmd_NetConnections@@" fullword ascii
		$s4 = "Corporation. All rights reserved." fullword wide
		$s5 = { 49 83 3c 24 00 75 02 eb 5d 49 8b 34 24 0f b7 46 }
		$op1 = { 44 24 57 6f c6 44 24 58 6e c6 44 24 59 }
		$op2 = { c6 44 24 56 64 88 5c 24 57 }
		$op3 = { 44 24 6d 4c c6 44 24 6e 6f c6 44 24 6f }

	condition:
		uint16(0)==0x5a4d and filesize <400KB and (2 of ($s*) or all of ($op*))
}
