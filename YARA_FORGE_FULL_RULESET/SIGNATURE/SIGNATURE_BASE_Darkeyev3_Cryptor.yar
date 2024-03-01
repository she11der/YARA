rule SIGNATURE_BASE_Darkeyev3_Cryptor : FILE
{
	meta:
		description = "Rule to detect DarkEYEv3 encrypted executables (often malware)"
		author = "Florian Roth (Nextron Systems)"
		id = "a2b455e5-3021-5662-b593-c1aeeb34c226"
		date = "2015-05-24"
		modified = "2023-12-05"
		reference = "http://darkeyev3.blogspot.fi/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/generic_cryptors.yar#L2-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "fdd3a9c22aebb40d000a642f2433adc7dd591784bdf2924edc3effce7bbfa5c2"
		score = 55
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash0 = "6b854b967397f7de0da2326bdd5d39e710e2bb12"
		hash1 = "d53149968eca654fc0e803f925e7526fdac2786c"
		hash2 = "7e3a8940d446c57504d6a7edb6445681cca31c65"
		hash3 = "d3dd665dd77b02d7024ac16eb0949f4f598299e7"
		hash4 = "a907a7b74a096f024efe57953c85464e87275ba3"
		hash5 = "b1c422155f76f992048377ee50c79fe164b22293"
		hash6 = "29f5322ce5e9147f09e0a86cc23a7c8dc88721b9"
		hash7 = "a0382d7c12895489cb37efef74c5f666ea750b05"
		hash8 = "f3d5b71b7aeeb6cc917d5bb67e2165cf8a2fbe61"

	strings:
		$s0 = "\\DarkEYEV3-"

	condition:
		uint16(0)==0x5a4d and $s0
}
