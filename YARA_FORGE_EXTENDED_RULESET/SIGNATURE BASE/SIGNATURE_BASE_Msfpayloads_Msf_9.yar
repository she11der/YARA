rule SIGNATURE_BASE_Msfpayloads_Msf_9 : FILE
{
	meta:
		description = "Metasploit Payloads - file msf.war - contents"
		author = "Florian Roth (Nextron Systems)"
		id = "488a2e97-ebc2-5ccf-ab5d-dfed4b534b52"
		date = "2017-02-09"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_metasploit_payloads.yar#L232-L252"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "b5761b51b79f83c48deafaf3786cb90ef493ab0448cd67b86655cecb0160a627"
		score = 75
		quality = 83
		tags = "FILE"
		hash1 = "e408678042642a5d341e8042f476ee7cef253871ef1c9e289acf0ee9591d1e81"

	strings:
		$s1 = "if (System.getProperty(\"os.name\").toLowerCase().indexOf(\"windows\") != -1)" fullword ascii
		$s2 = ".concat(\".exe\");" fullword ascii
		$s3 = "[0] = \"chmod\";" ascii
		$s4 = "= Runtime.getRuntime().exec(" ascii
		$s5 = ", 16) & 0xff;" ascii
		$x1 = "4d5a9000030000000" ascii

	condition:
		4 of ($s*) or ( uint32(0)==0x61356434 and $x1 at 0)
}
