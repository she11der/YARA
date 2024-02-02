rule BINARYALERT_Ransomware_Windows_Zcrypt
{
	meta:
		description = "Zcrypt will encrypt data and append the .zcrypt extension to the filenames"
		author = "@fusionrace"
		id = "d79cd266-4e77-562c-975c-8bf72efe7242"
		date = "2017-08-11"
		modified = "2017-08-11"
		reference = "https://blog.malwarebytes.com/threat-analysis/2016/06/zcrypt-ransomware/"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/ransomware/windows/ransomware_windows_zcrypt.yara#L1-L23"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		hash = "d1e75b274211a78d9c5d38c8ff2e1778"
		logic_hash = "df4073363da162e69f29493b5bfb4cb3f3d342357335c13ba6a3ac868607cb25"
		score = 75
		quality = 78
		tags = ""

	strings:
		$u1 = "How to Buy Bitcoins" ascii wide
		$u2 = "ALL YOUR PERSONAL FILES ARE ENCRYPTED" ascii wide
		$u3 = "Click Here to Show Bitcoin Address" ascii wide
		$u4 = "MyEncrypter2.pdb" fullword ascii wide
		$g1 = ".p7b" fullword ascii wide
		$g2 = ".p7c" fullword ascii wide
		$g3 = ".pdd" fullword ascii wide
		$g4 = ".pef" fullword ascii wide
		$g5 = ".pem" fullword ascii wide
		$g6 = "How to decrypt files.html" fullword ascii wide

	condition:
		any of ($u*) or all of ($g*)
}