rule SIGNATURE_BASE_Pirpi_1609_B : FILE
{
	meta:
		description = "Detects Pirpi Backdoor"
		author = "Florian Roth (Nextron Systems)"
		id = "caf63b97-efd7-5cd4-8954-b86db4d93cf5"
		date = "2016-09-08"
		modified = "2023-12-05"
		reference = "http://goo.gl/igxLyF"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_pirpi.yar#L45-L65"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "4dafff80fb7bfcffccf96d991245c13b3208fd4f5a21488d7d6885758ef05078"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "498b98c02e19f4b03dc6a3a8b6ff8761ef2c0fedda846ced4b6f1c87b52468e7"

	strings:
		$s1 = "tconn <ip> <port> //set temp connect value, and disconnect." fullword ascii
		$s2 = "E* ListenCheckSsl SslRecv fd(%d) Error ret:%d %d" fullword ascii
		$s3 = "%s %s L* ListenCheckSsl fd(%d) SslV(-%d-)" fullword ascii
		$s4 = "S:%d.%d-%d.%d V(%d.%d) Listen On %d Ok." fullword ascii
		$s5 = "E* ListenCheckSsl fd(%d) SslAccept Err %d" fullword ascii
		$s6 = "%s-%s N110 Ssl Connect Ok(%s:%d)." fullword ascii
		$s7 = "%s-%s N110 Basic Connect Ok(%s:%d)." fullword ascii
		$s8 = "tconn <ip> <port>" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and 2 of them ) or (4 of them )
}
