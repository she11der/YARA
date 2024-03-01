import "pe"

rule TRELLIX_ARC_Ransom_Tunderx : RANSOMWARE FILE
{
	meta:
		description = "Rule to detect tthe ThunderX ransomware family"
		author = "McAfee ATR team"
		id = "cf5ecd0c-db26-5fe4-a056-b5c1ca3b1d34"
		date = "2020-09-14"
		modified = "2020-10-12"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/Ransom_ThunderX.yar#L3-L45"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "f870616c4a35239a01129daad5f12469b2df39251ee4bc9fbeb5523f00231ece"
		score = 75
		quality = 68
		tags = "RANSOMWARE, FILE"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransomware:W32/ThunderX"
		actor_type = "Cybercrime"
		actor_group = "Unknown"
		hash1 = "7bab5dedef124803668580a59b6bf3c53cc31150d19591567397bbc131b9ccb6"
		hash2 = "0fbfdb8340108fafaca4c5ff4d3c9f9a2296efeb9ae89fcd9210e3d4c7239666"
		hash3 = "7527459500109b3bb48665236c5c5cb2ec71ba789867ad2b6417b38b9a46615e"

	strings:
		$pattern1 = "626364656469742E657865202F736574207B64656661756C747D20626F6F74737461747573706F6C6963792069676E6F7265616C6C6661696C75726573"
		$s3 = "776261646D696E2044454C4554452053595354454D53544154454241434B5550202D64656C6574654F6C64657374" ascii
		$s4 = "626364656469742E657865202F736574207B64656661756C747D207265636F76657279656E61626C6564204E6F" ascii
		$s5 = "776261646D696E2044454C4554452053595354454D53544154454241434B5550" ascii
		$s6 = "433A5C50726F6772616D2046696C65732028783836295C4D6963726F736F66742053514C20536572766572" ascii
		$s7 = "476C6F62616C5C33353335354641352D303745392D343238422D423541352D314338384341423242343838" ascii
		$s8 = "433A5C50726F6772616D2046696C65735C4D6963726F736F66742053514C20536572766572" ascii
		$s9 = "76737361646D696E2E6578652044656C65746520536861646F7773202F416C6C202F5175696574" ascii
		$s10 = "776D69632E65786520534841444F57434F5059202F6E6F696E746572616374697665" ascii
		$s11 = "534F4654574152455C4D6963726F736F66745C45524944" ascii
		$s12 = "AppPolicyGetProcessTerminationMethod" fullword ascii
		$s13 = "7B5041545445524E5F49447D" ascii
		$s14 = "726561646D652E747874" ascii
		$s15 = "226E6574776F726B223A22" ascii
		$s16 = "227375626964223A22" ascii
		$s17 = "226C616E67223A22" ascii
		$s18 = "22657874223A22" ascii
		$s19 = "69642E6B6579" ascii
		$s20 = "7B5549447D" ascii
		$seq0 = { eb 34 66 0f 12 0d 10 c4 41 00 f2 0f 59 c1 ba cc }
		$seq1 = { 6a 07 50 e8 51 ff ff ff 8d 86 d0 }
		$seq2 = { ff 15 34 81 41 00 eb 15 83 f8 fc 75 10 8b 45 f4 }

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and pe.imphash()=="ea7e408cd2a264fd13492973e97d8d70" and $pattern1 and 4 of them ) and all of ($seq*) or ( all of them )
}
