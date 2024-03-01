import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0E96837Dbe5F4548547203919B96Ac27 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "83258afe-66e0-56d1-8361-125a1142ffe4"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L432-L443"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "2eedcc1d782df3c078c20a275680c2ff724e5b7675890af1335ff22d6138ab25"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "d6c6a0a4a57af645c9cad90b57c696ad9ad9fcf9"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PLAN CORP PTY LTD" and pe.signatures[i].serial=="0e:96:83:7d:be:5f:45:48:54:72:03:91:9b:96:ac:27")
}
