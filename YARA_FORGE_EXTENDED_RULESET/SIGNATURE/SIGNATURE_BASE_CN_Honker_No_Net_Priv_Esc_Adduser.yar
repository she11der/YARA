rule SIGNATURE_BASE_CN_Honker_No_Net_Priv_Esc_Adduser : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file AddUser.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "0f99914c-9349-5870-a3e0-3a5079efdecf"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L1738-L1754"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "4c95046be6ae40aee69a433e9a47f824598db2d4"
		logic_hash = "743e67e2aa95830034db1afda1f346c30467c7b59e030ed27415e5127013be74"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "PECompact2" fullword ascii
		$s1 = "adduser" fullword ascii
		$s5 = "OagaBoxA" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <115KB and all of them
}
