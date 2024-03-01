rule SIGNATURE_BASE_No_Powershell : FILE
{
	meta:
		description = "Detects an C# executable used to circumvent PowerShell detection - file nps.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "362a61bc-2c10-5076-93be-9f8b5a9ae8ba"
		date = "2016-05-21"
		modified = "2023-12-05"
		reference = "https://github.com/Ben0xA/nps"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_nopowershell.yar#L8-L23"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "9fba467cfbf8cad0c8e6cf1e1c7eacd8b0be869ebe6c5180f50f5cdefa8b5bb5"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "64f811b99eb4ae038c88c67ee0dc9b150445e68a2eb35ff1a0296533ae2edd71"

	strings:
		$s1 = "nps.exe -encodedcommand {base64_encoded_command}" fullword wide
		$s2 = "c:\\Development\\ghps\\nps\\nps\\obj\\x86\\Release\\nps.pdb" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <40KB and (1 of ($s*))) or ( all of them )
}
