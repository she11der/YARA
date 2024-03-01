import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0Dfa4F0Cff90319951B019A4681Ebd2A : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "bbb0be70-de74-5da9-80d2-2ba474b7f472"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7170-L7182"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "d89cda38cf6149c004f7d7b307243567768cba73bd49979d7d4f92f902ef4508"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "b85aacac6afb0bef5b6f1d744cd8c278030e6a3e"
		hash1 = "4eca4e0d3c06e4889917a473229b368bae02f0135f0ac68e937a72fca431ac8a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "deepinstruction O" and pe.signatures[i].serial=="0d:fa:4f:0c:ff:90:31:99:51:b0:19:a4:68:1e:bd:2a")
}
