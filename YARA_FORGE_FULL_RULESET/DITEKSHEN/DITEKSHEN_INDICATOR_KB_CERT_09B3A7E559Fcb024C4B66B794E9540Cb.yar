import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_09B3A7E559Fcb024C4B66B794E9540Cb : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "5e1057d4-a40c-5e48-8965-91fd533c04dc"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4790-L4802"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "345abbb31986fe3f8f6b7eb05c73d4d42daa9df6a7706b9cd2fb4f8aac61d40b"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "59c60ade491c9eda994711b1fdb59510baad2ea3"
		hash1 = "b57d694b6d1f9e0634953e8f5c1e4faf84fb50be806a8887dd5b31bfd58a167f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Windscribe Limited" and pe.signatures[i].serial=="09:b3:a7:e5:59:fc:b0:24:c4:b6:6b:79:4e:95:40:cb")
}
