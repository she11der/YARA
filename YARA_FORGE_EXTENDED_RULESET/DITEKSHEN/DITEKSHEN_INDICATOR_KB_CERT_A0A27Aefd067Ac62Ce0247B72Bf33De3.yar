import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_A0A27Aefd067Ac62Ce0247B72Bf33De3 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "1e8db3c4-8d32-5a8d-96ac-785d8f703c7d"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2861-L2872"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "c49e1d8b1a2d0e27fd25574ce587f60770ecac75c1db437bf7538d2ff47c8d4c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "42c2842fa674fdca14c9786aaec0c3078a4f1755"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Cfbcdabfdbdccaaccadfeaacacf" and pe.signatures[i].serial=="a0:a2:7a:ef:d0:67:ac:62:ce:02:47:b7:2b:f3:3d:e3")
}
