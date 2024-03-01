import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Ee663737D82Df09C7038A6A6693A8323 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "c6684a9f-ca92-53e9-9723-9d2437a16fc6"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1086-L1097"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "4057374b73ef13b6f101b939e11569cf010896097fd9322ab490c73d6808fa6f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "dc934afe82adbab8583e393568f81ab32c79aeea"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "KREACIJA d.o.o." and pe.signatures[i].serial=="00:ee:66:37:37:d8:2d:f0:9c:70:38:a6:a6:69:3a:83:23")
}
