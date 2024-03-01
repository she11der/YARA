rule SIGNATURE_BASE_Buckeye_Osinfo : FILE
{
	meta:
		description = "Detects OSinfo tool used by the Buckeye APT group"
		author = "Florian Roth (Nextron Systems)"
		id = "e40a86d1-fd1a-5430-b7b7-8cc7ca128cc5"
		date = "2016-09-05"
		modified = "2023-12-05"
		reference = "http://www.symantec.com/connect/blogs/buckeye-cyberespionage-group-shifts-gaze-us-hong-kong"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_buckeye.yar#L10-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "782ae4293db0839190a9533d2c45baff92527867bfcd048ccae82611f165601b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "-s ShareInfo ShareDir" fullword ascii
		$s2 = "-a Local And Global Group User Info" fullword ascii
		$s3 = "-f <infile> //input server list from infile, OneServerOneLine" fullword ascii
		$s4 = "info <\\server> <user>" fullword ascii
		$s5 = "-c Connect Test" fullword ascii
		$s6 = "-gd Group Domain Admins" fullword ascii
		$s7 = "-n NetuseInfo" fullword ascii

	condition:
		uint16(0)==0x5a4d and 3 of ($s*)
}
