rule BINARYALERT_Hacktool_Macos_Ptoomey3_Keychain_Dumper
{
	meta:
		description = "Keychain dumping utility."
		author = "@mimeframe"
		id = "c45abbbe-f5fe-5a87-acd4-dcdb99ceec28"
		date = "2017-09-12"
		modified = "2017-09-12"
		reference = "https://github.com/ptoomey3/Keychain-Dumper"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/macos/hacktool_macos_ptoomey3_keychain_dumper.yara#L1-L15"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "f2ef979e4682ce617b37f7503ec2ca520e657b4f6d15a75afad59b62191a1a43"
		score = 75
		quality = 80
		tags = ""

	strings:
		$a1 = "keychain_dumper" wide ascii
		$a2 = "/var/Keychains/keychain-2.db" wide ascii
		$a3 = "<key>keychain-access-groups</key>" wide ascii
		$a4 = "SELECT DISTINCT agrp FROM genp UNION SELECT DISTINCT agrp FROM inet" wide ascii
		$a5 = "dumpEntitlements" wide ascii

	condition:
		all of ($a*)
}
