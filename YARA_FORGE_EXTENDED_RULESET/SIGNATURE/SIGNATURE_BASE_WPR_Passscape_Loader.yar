import "pe"

rule SIGNATURE_BASE_WPR_Passscape_Loader : FILE
{
	meta:
		description = "Windows Password Recovery - file ast.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "d8e224ce-edd2-5e2d-9b6e-a8995f5d2c1c"
		date = "2017-03-15"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L3530-L3548"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "79b1a3ed1ea0d9a3ddee0b8557393318a8baf4812110a6ed03a7106b8096b31e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "f6f2d4b9f19f9311ec419f05224a1c17cf2449f2027cb7738294479eea56e9cb"

	strings:
		$s1 = "SYSTEM\\CurrentControlSet\\Services\\PasscapeLoader64" fullword wide
		$s2 = "ast64.dll" fullword ascii
		$s3 = "\\loader64.exe" wide
		$s4 = "Passcape 64-bit Loader Service" fullword wide
		$s5 = "PasscapeLoader64" fullword wide
		$s6 = "ast64 {msg1GkjN7Sh8sg2Al7ker63f}" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 2 of them )
}
