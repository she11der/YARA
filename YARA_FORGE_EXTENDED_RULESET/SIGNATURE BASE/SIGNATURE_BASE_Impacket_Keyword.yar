import "pe"

rule SIGNATURE_BASE_Impacket_Keyword : FILE
{
	meta:
		description = "Detects Impacket Keyword in Executable"
		author = "Florian Roth (Nextron Systems)"
		id = "a92962e6-1b05-583b-8b06-f226bdea88e2"
		date = "2017-08-04"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L3894-L3911"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "92a911dc36f8e74ad49ae09ef4dd997b968a2dde46a7500c98983fafb84a086e"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "9388c78ea6a78dbea307470c94848ae2481481f593d878da7763e649eaab4068"
		hash2 = "2f6d95e0e15174cfe8e30aaa2c53c74fdd13f9231406b7103da1e099c08be409"

	strings:
		$s1 = "impacket.smb(" ascii
		$s2 = "impacket.ntlm(" ascii
		$s3 = "impacket.nmb(" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <14000KB and 1 of them )
}
