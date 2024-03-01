import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Ea734E1Dfb6E69Ed2Bc55E513Bf95B5E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "4e40ce70-d5d1-5719-bb43-40f860510093"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7153-L7168"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "e2d07a2af36608d6eab6db85bcb968e486293239d0cfaeea7de2bb8223e58a29"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "5ca53cc5c6dc47838bbba922ad217a468408a9bd"
		hash1 = "293a83bfe2839bfa6d40fa52f5088e43b62791c08343c3f4dade4f1118000392"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Postmarket LLC" and (pe.signatures[i].serial=="00:ea:73:4e:1d:fb:6e:69:ed:2b:c5:5e:51:3b:f9:5b:5e" or pe.signatures[i].serial=="ea:73:4e:1d:fb:6e:69:ed:2b:c5:5e:51:3b:f9:5b:5e"))
}
