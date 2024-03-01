rule SIGNATURE_BASE_Msfpayloads_Msf_2
{
	meta:
		description = "Metasploit Payloads - file msf.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "ec1ae1b6-18a3-5590-ae15-1e2b362c545a"
		date = "2017-02-09"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_metasploit_payloads.yar#L25-L40"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "8f803a5d71a084e1ea453638bdeaa2dd590a1912be652b74b065d9afd332ffa2"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "e52f98466b92ee9629d564453af6f27bd3645e00a9e2da518f5a64a33ccf8eb5"

	strings:
		$s1 = "& \"\\\" & \"svchost.exe\"" fullword ascii
		$s2 = "CreateObject(\"Wscript.Shell\")" fullword ascii
		$s3 = "<% @language=\"VBScript\" %>" fullword ascii

	condition:
		all of them
}
