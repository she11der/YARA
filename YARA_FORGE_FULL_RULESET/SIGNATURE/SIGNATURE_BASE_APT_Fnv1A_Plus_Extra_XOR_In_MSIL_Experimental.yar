rule SIGNATURE_BASE_APT_Fnv1A_Plus_Extra_XOR_In_MSIL_Experimental : FILE
{
	meta:
		description = "This rule detects the specific MSIL implementation of fnv1a of the SUNBURST backdoor (standard fnv1a + one final XOR before RET) independent of the XOR-string. (fnv64a_offset and fnv64a_prime are standard constants in the fnv1a hashing algorithm.)"
		author = "Arnim Rupp"
		id = "5505f7ff-eca5-5274-bdd1-dbbd648c3ccc"
		date = "2020-12-22"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_backdoor_sunburst_fnv1a_experimental.yar#L2-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "6db212b21fec8d2c1b4cff9e32bdc027835ed660e7552b49f4418e7d0b35ca11"
		score = 50
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77"
		hash2 = "ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6"
		hash3 = "019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134"

	strings:
		$fnv64a_offset = { 25 23 22 84 e4 9c f2 cb }
		$fnv64a_prime_plus_gap_plus_xor_ret = { B3 01 00 00 00 01 [8-40] 61 2A 00 00 }

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}
