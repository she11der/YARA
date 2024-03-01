import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0092D9B92F8Cf7A1Ba8B2C025Be730C300 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "856b4522-f314-5cbb-872e-08b21107881b"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1884-L1895"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "207fcc48053afb6a435c40fd8e25a88753139c35f4882a1975fdb8c55dc8ea89"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "b891c96bd8548c60fa86b753f0c4a4ccc7ab51256b4ee984b5187c62470f9396"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "UPLagga Systems s.r.o." and pe.signatures[i].serial=="00:92:d9:b9:2f:8c:f7:a1:ba:8b:2c:02:5b:e7:30:c3:00")
}
