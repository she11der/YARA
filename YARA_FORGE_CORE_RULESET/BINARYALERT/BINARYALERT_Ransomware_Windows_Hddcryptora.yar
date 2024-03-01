rule BINARYALERT_Ransomware_Windows_Hddcryptora
{
	meta:
		description = "The HDDCryptor ransomware encrypts local harddisks as well as resources in network shares via Server Message Block (SMB)"
		author = "@fusionrace"
		id = "56d7f1f5-811d-58c9-9e1d-d2f48c01e167"
		date = "2017-08-11"
		modified = "2017-08-11"
		reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/bksod-by-ransomware-hddcryptor-uses-commercial-tools-to-encrypt-network-shares-and-lock-hdds/"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/ransomware/windows/ransomware_windows_HDDCryptorA.yara#L1-L23"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		hash = "498bdcfb93d13fecaf92e96f77063abf"
		logic_hash = "24c113be31c3df7b544a5789bf055f77471d450c07f0a6729a715e2a82b4d1f0"
		score = 75
		quality = 78
		tags = ""

	strings:
		$u1 = "You are Hacked" fullword ascii wide
		$u2 = "Your H.D.D Encrypted , Contact Us For Decryption Key" nocase ascii wide
		$u3 = "start hard drive encryption..." ascii wide
		$u4 = "Your hard drive is securely encrypted" ascii wide
		$g1 = "Wipe All Passwords?" ascii wide
		$g2 = "SYSTEM\\CurrentControlSet\\Services\\dcrypt\\config" ascii wide
		$g3 = "DiskCryptor" ascii wide
		$g4 = "dcinst.exe" fullword ascii wide
		$g5 = "dcrypt.exe" fullword ascii wide
		$g6 = "you can only use AES to encrypt the boot partition!" ascii wide

	condition:
		2 of ($u*) or 4 of ($g*)
}
