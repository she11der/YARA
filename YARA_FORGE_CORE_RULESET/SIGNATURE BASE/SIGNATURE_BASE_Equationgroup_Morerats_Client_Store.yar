rule SIGNATURE_BASE_Equationgroup_Morerats_Client_Store : FILE
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth (Nextron Systems)"
		id = "de6de983-fad2-58cf-95be-57109436d5fc"
		date = "2017-04-09"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L1417-L1433"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "34dc21d933d56b6f6c342ca110d9cff7bb51d9fd1b88b359861e5b5650679ad0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "619944358bc0e1faffd652b6af0600de055c5e7f1f1d91a8051ed9adf5a5b465"

	strings:
		$s1 = "[-] Failed to mmap file: %s" fullword ascii
		$s2 = "[-] can not NULL terminate input data" fullword ascii
		$s3 = "Missing argument for `-x'." fullword ascii
		$s4 = "[!] Value has size of 0!" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <60KB and 2 of them )
}
