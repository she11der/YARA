rule SIGNATURE_BASE_Msfpayloads_Msf_Exe
{
	meta:
		description = "Metasploit Payloads - file msf-exe.vba"
		author = "Florian Roth (Nextron Systems)"
		id = "fd07240e-0ee0-5318-a436-d97054e92414"
		date = "2017-02-09"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_metasploit_payloads.yar#L59-L77"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "3baa242e90dd845e022785101ebc2d5c0d84007d20aef6a2bb6a9a8c6280d4eb"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "321537007ea5052a43ffa46a6976075cee6a4902af0c98b9fd711b9f572c20fd"

	strings:
		$s1 = "'* PAYLOAD DATA" fullword ascii
		$s2 = " = Shell(" ascii
		$s3 = "= Environ(\"USERPROFILE\")" fullword ascii
		$s4 = "'**************************************************************" fullword ascii
		$s5 = "ChDir (" ascii
		$s6 = "'* MACRO CODE" fullword ascii

	condition:
		4 of them
}
