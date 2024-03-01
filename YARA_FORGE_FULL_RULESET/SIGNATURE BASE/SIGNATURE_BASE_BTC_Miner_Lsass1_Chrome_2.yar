rule SIGNATURE_BASE_BTC_Miner_Lsass1_Chrome_2 : FILE
{
	meta:
		description = "Detects a Bitcoin Miner"
		author = "Florian Roth (Nextron Systems)"
		id = "7960d96a-7bd3-5135-867d-e39a02274c45"
		date = "2017-06-22"
		modified = "2023-12-05"
		reference = "Internal Research - CN Actor"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/crime_cn_group_btc.yar#L10-L27"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ef80dba71c901d6e821b2e08a701a82f8147e41a8f14c5fd324d5e043b0ff322"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "048e9146387d6ff2ac055eb9ddfbfb9a7f70e95c7db9692e2214fa4bec3d5b2e"
		hash2 = "c8db8469287d47ffdc74fe86ce0e9d6e51de67ba1df318573c9398742116a6e8"

	strings:
		$x1 = "-t, --threads=N       number of miner threads (default: number of processors)" fullword ascii
		$x2 = "-O, --userpass=U:P    username:password pair for mining server" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <6000KB and 1 of them )
}
