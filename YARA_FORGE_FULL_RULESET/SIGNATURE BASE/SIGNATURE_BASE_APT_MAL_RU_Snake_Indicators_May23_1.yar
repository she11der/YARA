rule SIGNATURE_BASE_APT_MAL_RU_Snake_Indicators_May23_1
{
	meta:
		description = "Detects indicators found in Snake malware samples"
		author = "Florian Roth"
		id = "0d4fa8a7-447c-5905-bab9-b63de6209036"
		date = "2023-05-10"
		modified = "2023-12-05"
		reference = "https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_mal_ru_snake_may23.yar#L44-L79"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "cb7a4ad2ee0868f17b6235f070e4c03e2394e3c252253f334b29ad26116b09e5"
		score = 85
		quality = 35
		tags = ""
		hash1 = "10b854d66240d9ee1ce4296d2f7857d2b1c6f062ca836d13d777930d678b3ca6"
		hash2 = "15ac5a61fb3e751045de2d7f5ff26c673f3883e326cd1b3a63889984a4fb2a8f"
		hash3 = "315ec991709eb45eccf724dfe31bccb7affcac7f8e8007e688ba8d02827205e0"
		hash4 = "417eb4fb9ada270af35562ff317807ac5ca9ee26181fe89990858f0944d3a6a7"
		hash5 = "48112970de6ea0f925f0657b30adcd0723df94afc98cfafdc991d70ad3602119"
		hash6 = "55ea557bcf4c143f20c616abe9075f7faafbf825aeef9ddb4f2b201acc44414b"
		hash7 = "6568bbeeb417e1111bf284e73152d90fe17e5497da7630ccddcbc666730dccef"
		hash8 = "81d620cb645006ffc9ac1b9d98a53aa286ae92b025bda075962079633f020482"
		hash9 = "888a3029b1b8b664eb1fc77dd511c4088a1e28ae5535a8683642bb3dca011d00"
		hash10 = "9027b4fef50b36289d630059425dc1137c88328329c3ea9dbc348dccd001adc0"
		hash11 = "9ac199572cab67433726976a0e9ba39d6feed1d567d6d230ebe3133df8dcb7fa"
		hash12 = "a64e5d872421991226ee040b4cd49a89ca681bdef4c10c4798b6c7b5c832c6df"
		hash13 = "b5d2da5eb57b5ab26edb927469552629f3cf43bbce2b1a128f6daac7cf57f6f7"
		hash14 = "bc15de1d1c6c62c0bf856e0368adabc4941e7b687a969912494c173233e6d28d"
		hash15 = "bdf94311313c39a3413464f623bd75a3db2eb05cc01090acd6dcd462a605eb4a"
		hash16 = "e4311892ae00bf8148a94fa900fc8e2c279a2acd3b4b4b4c3d0c99dd1d32353c"
		hash17 = "ed74288b367a93c6b47343bc696e751b9c465761ce9c4208901726baa758b234"
		hash18 = "ef1f1c7692b92a730f76b6227643b2d02a6e353af6e930166e3b48e3903e4ffd"
		hash19 = "f5e982b76af7f447742753f0b57eec3d7dd2e3c8e5506c35d4cf6c860b829f45"

	strings:
		$s1 = "\\\\.\\%s\\\\" ascii fullword
		$s2 = "read_peer_nfo" ascii fullword
		$s3 = "rcv_buf=%d%c" ascii fullword
		$s4 = "%s: (0x%08x)" ascii fullword
		$s5 = "no_impersonate" ascii fullword

	condition:
		all of them
}
