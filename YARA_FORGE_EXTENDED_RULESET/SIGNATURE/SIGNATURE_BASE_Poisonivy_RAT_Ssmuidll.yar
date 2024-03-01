rule SIGNATURE_BASE_Poisonivy_RAT_Ssmuidll : FILE
{
	meta:
		description = "Detects PoisonIvy RAT DLL mentioned in Palo Alto Blog in April 2016"
		author = "Florian Roth (Nextron Systems) (with the help of yarGen and Binarly)"
		id = "f2535b70-cf17-5435-9fc8-2dfdf70d95ac"
		date = "2016-04-22"
		modified = "2023-12-05"
		reference = "http://goo.gl/WiwtYT"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_poisonivy.yar#L196-L230"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "d048d88cac40f4fe3affee8d9dad35a7347a5459fbdd56b08a77ece4f6c2ac08"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "7a424ad3f3106b87e8e82c7125834d7d8af8730a2a97485a639928f66d5f6bf4"
		hash2 = "6eb7657603edb2b75ed01c004d88087abe24df9527b272605b8517a423557fe6"
		hash3 = "2a6ef9dde178c4afe32fe676ff864162f104d85fac2439986de32366625dc083"
		hash4 = "8b805f508879ecdc9bba711cfbdd570740c4825b969c1b4db980c134ac8fef1c"
		hash5 = "ac99d4197e41802ff9f8852577955950332947534d8e2a0e3b6c1dd1715490d4"

	strings:
		$s1 = "ssMUIDLL.dll" fullword ascii
		$op1 = { 6a 00 c6 07 e9 ff d6 }
		$op2 = { 02 cb 6a 00 88 0f ff d6 47 ff 4d fc 75 }
		$op3 = { 6a 00 88 7f 02 ff d6 }

	condition:
		( uint16(0)==0x5a4d and filesize <20KB and ( all of ($op*))) or ( all of them )
}
