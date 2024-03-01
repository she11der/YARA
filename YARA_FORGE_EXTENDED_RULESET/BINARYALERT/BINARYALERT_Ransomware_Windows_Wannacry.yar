rule BINARYALERT_Ransomware_Windows_Wannacry
{
	meta:
		description = "wannacry ransomware for windows"
		author = "@fusionrace"
		id = "0269b6f4-a47d-5683-aaaa-2141ca7f04dc"
		date = "2017-08-11"
		modified = "2017-08-11"
		reference = "https://securelist.com/blog/incidents/78351/wannacry-ransomware-used-in-widespread-attacks-all-over-the-world/"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/ransomware/windows/ransomware_windows_wannacry.yara#L1-L23"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		hash = "4fef5e34143e646dbf9907c4374276f5"
		logic_hash = "c01f460c0f5e39cde5f553c966553fe693e5203cb020b8f571eac6fc193fa91b"
		score = 75
		quality = 50
		tags = ""

	strings:
		$a1 = "msg/m_chinese" wide ascii
		$a2 = ".wnry" wide ascii
		$a3 = "attrib +h" wide ascii
		$b1 = "WNcry@2ol7" wide ascii
		$b2 = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" wide ascii
		$b3 = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn" wide ascii
		$b4 = "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw" wide ascii
		$b5 = "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94" wide ascii

	condition:
		all of ($a*) or any of ($b*)
}
