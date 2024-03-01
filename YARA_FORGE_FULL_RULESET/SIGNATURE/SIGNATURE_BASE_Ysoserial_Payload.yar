rule SIGNATURE_BASE_Ysoserial_Payload : FILE
{
	meta:
		description = "Ysoserial Payloads"
		author = "Florian Roth (Nextron Systems)"
		id = "c269e032-b6ce-5faa-b3ce-a5304f3e9dab"
		date = "2017-02-04"
		modified = "2023-12-05"
		reference = "https://github.com/frohoff/ysoserial"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_ysoserial_payloads.yar#L61-L90"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "eec48af8bd3b377c8dd5af71027f67b36e1bd4d4ccfbd8134a26783517b5585a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "9c0be107d93096066e82a5404eb6829b1daa6aaa1a7b43bcda3ddac567ce715a"
		hash2 = "adf895fa95526c9ce48ec33297156dd69c3dbcdd2432000e61b2dd34ffc167c7"
		hash3 = "1da04d838141c64711d87695a4cdb4eedfd4a206cc80922a41cfc82df8e24187"
		hash4 = "5c44482350f1c6d68749c8dec167660ca6427999c37bfebaa54f677345cdf63c"
		hash5 = "747ba6c6d88470e4d7c36107dfdff235f0ed492046c7ec8a8720d169f6d271f4"
		hash6 = "f0d2f1095da0164c03a0e801bd50f2f06793fb77938e53b14b57fd690d036929"
		hash7 = "5466d47363e11cd1852807b57d26a828728b9d5a0389214181b966bd0d8d7e56"
		hash8 = "95f966f2e8c5d0bcdfb34e603e3c0b911fa31fc960308e41fcd4459e4e07b4d1"
		hash9 = "1fea8b54bb92249203d68d5564a01599b42b46fc3a828fe0423616ee2a2f2d99"
		hash10 = "0143fee12fea5118be6dcbb862d8ba639790b7505eac00a9f1028481f874baa8"
		hash11 = "8cfa85c16d37fb2c38f277f39cafb6f0c0bd7ee62b14d53ad1dd9cb3f4b25dd8"
		hash12 = "bf9b5f35bc1556d277853b71da24faf23cf9964d77245018a0fdf3359f3b1703"
		hash13 = "f756c88763d48cb8d99e26b4773eb03814d0bd9bd467cc743ebb1479b2c4073e"

	strings:
		$x1 = "ysoserial/payloads/" ascii
		$s1 = "StubTransletPayload" fullword ascii
		$s2 = "Pwnrpw" fullword ascii

	condition:
		( uint16(0)==0xedac and filesize <40KB and $x1) or ( all of them )
}
