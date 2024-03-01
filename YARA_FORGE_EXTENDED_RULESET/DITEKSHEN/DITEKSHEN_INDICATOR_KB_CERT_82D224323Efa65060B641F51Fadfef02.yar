import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_82D224323Efa65060B641F51Fadfef02 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "2c0b0e6d-2c82-506b-88ea-a6d49f0f64a6"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7696-L7710"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "3ed849dfd905e01145274d41b3bbb2c0265b099e540ac17909b6ed59f006e245"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "8dccf6ad21a58226521e36d7e5dbad133331c181"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SAVAS INVESTMENTS PTY LTD" and (pe.signatures[i].serial=="82:d2:24:32:3e:fa:65:06:0b:64:1f:51:fa:df:ef:02" or pe.signatures[i].serial=="00:82:d2:24:32:3e:fa:65:06:0b:64:1f:51:fa:df:ef:02"))
}
