rule SIGNATURE_BASE_Coinhive_Javascript_Monerominer : HIGHVOL FILE
{
	meta:
		description = "Detects CoinHive - JavaScript Crypto Miner"
		author = "Florian Roth (Nextron Systems)"
		id = "4f40c342-fcdc-5c73-a3cf-7b2ed438eaaf"
		date = "2018-01-04"
		modified = "2023-12-05"
		reference = "https://coinhive.com/documentation/miner"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/pua_cryptocoin_miner.yar#L20-L33"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "4146b034a9785f1bb7c60db62db0e478d960f2ac9adb7c5b74b365186578ca47"
		score = 50
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "CoinHive.CONFIG.REQUIRES_AUTH" fullword ascii

	condition:
		filesize <65KB and 1 of them
}
