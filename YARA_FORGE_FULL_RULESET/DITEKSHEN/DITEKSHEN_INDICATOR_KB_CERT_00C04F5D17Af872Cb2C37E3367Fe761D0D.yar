import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00C04F5D17Af872Cb2C37E3367Fe761D0D : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "9d008f04-8d02-5c6b-b38d-234409cce277"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1504-L1518"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "7fa0d16600ae89e41d7b2b0655b142ea36202e8bbbf5f8e25cbb45a005995e79"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "7f52ece50576fcc7d66e028ecec89d3faedeeedb953935e215aac4215c9f4d63"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DES SP Z O O" and (pe.signatures[i].serial=="00:c0:4f:5d:17:af:87:2c:b2:c3:7e:33:67:fe:76:1d:0d" or pe.signatures[i].serial=="c0:4f:5d:17:af:87:2c:b2:c3:7e:33:67:fe:76:1d:0d"))
}
