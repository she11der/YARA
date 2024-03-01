rule SIGNATURE_BASE_Mal_Http_EXE : FILE
{
	meta:
		description = "Detects trojan from APT report named http.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "bcae9920-56ea-54a1-857b-70c275090e19"
		date = "2016-05-25"
		modified = "2023-01-27"
		reference = "https://goo.gl/13Wgy1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_danti_svcmondr.yar#L27-L58"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "0e28b64bbfd2b6d40f4bd82373624d22df3d5c45c22d7155747f0ff33976207d"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "ad191d1d18841f0c5e48a5a1c9072709e2dd6359a6f6d427e0de59cfcd1d9666"

	strings:
		$x1 = "Content-Disposition: form-data; name=\"file1\"; filename=\"%s\"" fullword ascii
		$x2 = "%ALLUSERSPROFILE%\\Accessories\\wordpade.exe" fullword ascii
		$x3 = "\\dumps.dat" ascii
		$x4 = "\\wordpade.exe" ascii
		$x5 = "\\%s|%s|4|%d|%4d-%02d-%02d %02d:%02d:%02d|" ascii
		$x6 = "\\%s|%s|5|%d|%4d-%02d-%02d %02d:%02d:%02d|" ascii
		$x7 = "cKaNBh9fnmXgJcSBxx5nFS+8s7abcQ==" fullword ascii
		$x8 = "cKaNBhFLn1nXMcCR0RlbMQ==" fullword ascii
		$s1 = "SELECT * FROM moz_logins;" fullword ascii
		$s2 = "makescr.dat" fullword ascii
		$s3 = "%s\\Mozilla\\Firefox\\profiles.ini" fullword ascii
		$s4 = "?moz-proxy://" ascii
		$s5 = "[%s-%s] Title: %s" fullword ascii
		$s6 = "Cforeign key mismatch - \"%w\" referencing \"%w\"" fullword ascii
		$s7 = "Windows 95 SR2" fullword ascii
		$s8 = "\\|%s|0|0|" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and (1 of ($x*) and 2 of ($s*))) or (3 of ($x*))
}
