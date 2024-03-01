rule SIGNATURE_BASE_Rombertik_Carbongrabber_Builder : FILE
{
	meta:
		description = "Detects CarbonGrabber alias Rombertik Builder - file Builder.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "3233c139-ac06-576c-9870-51306d5aa385"
		date = "2015-05-05"
		modified = "2023-12-05"
		reference = "http://blogs.cisco.com/security/talos/rombertik"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/crime_rombertik_carbongrabber.yar#L75-L92"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "b50ecc0ba3d6ec19b53efe505d14276e9e71285f"
		logic_hash = "e9d13913ee03926920eba33a4dac2a6e9aeaaa54949c5bfea8dd956cf233abae"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "c:\\users\\iden\\documents\\visual studio 2010\\Projects\\FormGrabberBuilderC++" ascii
		$s1 = "Host(www.panel.com): " fullword ascii
		$s2 = "Path(/form/index.php?a=insert): " fullword ascii
		$s3 = "FileName: " fullword ascii
		$s4 = "~Rich8" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <35KB and all of them
}
