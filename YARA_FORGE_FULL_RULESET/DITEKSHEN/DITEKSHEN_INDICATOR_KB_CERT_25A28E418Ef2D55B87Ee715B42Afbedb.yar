import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_25A28E418Ef2D55B87Ee715B42Afbedb : FILE
{
	meta:
		description = "VMProtect Software CA Certificate"
		author = "ditekSHen"
		id = "dc0b80f1-c720-5d83-a92b-144b1fd05138"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6431-L6442"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "be40d3b202b400eda7e78280b674823f789e292a35f0892ab3a323d1b055e789"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "14e375bd4a40ddd3310e05328dda16e84bac6d34"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Enigma Protector CA" and pe.signatures[i].serial=="25:a2:8e:41:8e:f2:d5:5b:87:ee:71:5b:42:af:be:db")
}
