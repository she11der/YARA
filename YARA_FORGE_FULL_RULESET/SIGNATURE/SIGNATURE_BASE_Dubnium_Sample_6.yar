rule SIGNATURE_BASE_Dubnium_Sample_6 : FILE
{
	meta:
		description = "Detects sample mentioned in the Dubnium Report"
		author = "Florian Roth (Nextron Systems)"
		id = "43366f1a-784d-515e-a8e9-3e924f2abfd8"
		date = "2016-06-10"
		modified = "2023-12-05"
		reference = "https://goo.gl/AW9Cuu"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_dubnium.yar#L89-L107"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "3425734b3259ebd5390cf16d2e394a4cc735dc3fc9fcc627b46bcc77729e465e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "5246899b8c74a681e385cbc1dd556f9c73cf55f2a0074c389b3bf823bfc6ce4b"
		hash2 = "5f07b074414513b73e202d7f77ec4bcf048f13dd735c9be3afcf25be818dc8e0"
		hash3 = "839baf85de657b6d6503b6f94054efa8841f667987a9c805eab94a85a859e1ba"

	strings:
		$s1 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&()`~-_=+[{]{;',." fullword ascii
		$s2 = "e_$0[bW\\RZY\\jb\\ZY[nimiRc[jRZ]" fullword ascii
		$s3 = "f_RIdJ0W9RFb[$Fbc9[k_?Wn" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <4000KB and all of them
}
